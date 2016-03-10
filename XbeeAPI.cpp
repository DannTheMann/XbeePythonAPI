
// APPENDING PAYLOADS
// TRANSMIT STATUS PACKETS
// METHODS TO HANLDE HB requests

#include "Arduino.h"
#include "XbeeAPI.h"

/*
* XbeeAPI
*/

XbeeAPI::XbeeAPI(HardwareSerial *pserial, int pin, const char* name) : name(name)
{
  serial = pserial;
  serial->begin(9600);
  serial->setTimeout(1000);
}

#define MAX_TRANSMIT_RF_DATA 72

uint8_t XbeeAPI::sendMessage(unsigned char* message)
{
   int len = strlen((char*)message);
   unsigned char framesNeeded = len / 72;
   if ( len > 72 && len < 144){
      framesNeeded++;
   }else if(len > 0 && len < 72){
      framesNeeded = 1;
   }

   if(framesNeeded > 255){
      return 3; // Too large a message
   }

   unsigned char frame[150];
   unsigned char escapedFrame[200];

   for (int i = 0; i < framesNeeded; i++){

      int escapedLen = produceFrame(escapedFrame, frame, message, len, i);

      serial->write(escapedFrame, escapedLen);
      // Clear both char arrays with 0's
      memset(frame, 0, 150);
      memset(escapedFrame, 0, 200);
      delay(250);

      if (txstatus != NULL && txstatus->wasSuccessful())
        continue;
      else{
        i--;
        continue;
      }

   }

 }

bool XbeeAPI::responseReady()
{
  return true;
}

unsigned char* XbeeAPI::getResponse()
{
  return message->getPayload();
}

int XbeeAPI::produceFrame(unsigned char* escapedFrame, unsigned char* frame, unsigned char* message, int len, int id)
{

      frame[0] = 0x7E; // Starting delimiter
      frame[1] = 0x00; // MSB Length
      frame[3] = 0x10; // Frame type, transmit
      frame[4] = 0x01; // Frame ID = 1;

      // Coordinator address (64 bit address)
      frame[5] = 0x00;
      frame[6] = 0x00;
      frame[7] = 0x00;
      frame[8] = 0x00;
      frame[9] = 0x00;
      frame[10] = 0x00;
      frame[11] = 0x00;
      frame[12] = 0x00;
      // 16 bit address
      frame[13] = 0xFF;
      frame[14] = 0xFE;
      // Options
      frame[15] = 0x00;
      // RF Data
      frame[16] = id; // Unique Frame ID
      int length = (id+1) * MAX_TRANSMIT_RF_DATA;
      bool final = false;
      if(length >= len){
        final = true;
        length = len;
      }

      int k = 17;
      for(int j = id * MAX_TRANSMIT_RF_DATA; j < length; j++){
          frame[k++] = message[j];
      }

      if(final){
        frame[k++] = '!';
      }

      int checksum = 0;
      for(int i = 3; i < k; i++){
          checksum+=frame[i];
      }
      frame[k] = checksum;

      return escape(frame, escapedFrame);
  
}

#define INPUT_SIZE 200

void XbeeAPI::poll()
{

    unsigned char input[INPUT_SIZE + 1]; // Total length of data expected, including + 1 for termination \0
    delay(250);
    uint8_t size = serial->readBytes(input, INPUT_SIZE);
    input[size] = 0; // Final termination of array \0

    const char *delim = "\x7E";
    unsigned char* packet = (unsigned char*)strtok((char*)input, delim);


    while(packet != 0){

      if (validatePacket(packet)){
        packet = (unsigned char*)strtok((char*)input, delim);
      }else{
        for(int i = 0; i < INPUT_SIZE; i++){
          if(packet[i] == 0){
            input[i] = 0;
            break;
          }
          input[i] = packet[i];
        }
        break;
      }

    }
}

bool XbeeAPI::validatePacket(unsigned char* packet){

      unsigned char output[INPUT_SIZE];

      unescape(packet, output);

      if(output[0] != 0x00)
        return false;

      unsigned char len = output[1];
      unsigned char actualLen = strlen((char*)output);

      if(len != actualLen-3)
        return false;

      unsigned char checkSum = output[len-1];
      unsigned char calculatedCheckSum = 0;
      len+=2;
      for(int i=2;i<len;i++){
        calculatedCheckSum+=output[i];
      }

      if(checkSum != 0xFF){
        return false;
      }

      unsigned char frameType = output[2];

      if(frameType == 0x10){ // RxPacket

        if(message == NULL || message->hasTerminated()){
          if(message != NULL){
            delete message;
          }
          message = new RxMessage();
        }
        unsigned char response = message->appendPayload(output);

        if(response == 1){
          char str[20];
          strcpy(str, "HB#:");
          strcat(str, name);
          strcat(str, "!");
          sendMessage((unsigned char*)str);
        }
        

      }else if(frameType == 0x8B) {// TxStatus packet
        if(txstatus != NULL){
          delete txstatus;
        }
        txstatus = new TxStatus(output);
      }else{
        return false; // Invalid packet
      }



}

void XbeeAPI::unescape(unsigned char* packet, unsigned char* output)
{

  unsigned char len = INPUT_SIZE; // Worst case scenario, we know the maximum size of the array
  unsigned char index = 1;
  unsigned char out = 1;
  output[0] = packet[0];

  if ( packet[1] == 0x7D) {// The length has been escaped, so we need unescape and determine it
      len = packet[2] ^ 0x20; // Get the original length 
      index = 3;
  }else{
      len = packet[1];
      index = 2;
  }
  output[1] = len; 

  len += index+1; // account for the previous bytes before the payload as well as checksum
  bool skip = false;
  // i = 3 as we know...
  // 0 is the MSB of length = 0 
  // 1 is the LSB of length, i.e our 
  while(index < len){ // Iterate through the length of the packet

    if(skip){
        skip = false;
        continue;
    }

    if(packet[index] != 0x7D){
      output[out++] = packet[index++]; 
    }else{
      output[out++] = packet[index+1] ^ 0x20;
      skip = true;
    }

  }

}

unsigned char XbeeAPI::escape(unsigned char* packet, unsigned char* output)
{
  
  unsigned char len = packet[2];
  unsigned char pos = 1;

  output[0] = 0x7E;
  for(int i = 1; i < (len+4); i++){
    switch(packet[i]){
      case 0x7D:
      case 0x7E:
      case 0x11:
      case 0x13:
          output[pos++] = 0x7D;
          output[pos++] = packet[i] ^ 0x20;
          break;
      default:
          output[pos++] = packet[i];
          break;
    }
  }

  return pos+1;

}


/*
* TxStatus
*/
XbeeAPI::TxStatus::TxStatus(unsigned char* packet)
{
  delivery = packet[7];
}

bool XbeeAPI::TxStatus::wasSuccessful()
{
  return getDeliveryStatus();
}

uint8_t XbeeAPI::TxStatus::getDeliveryStatus()
{
  return delivery == 0;
}

/*
* RxMessage
*/
#define PACKET_SIZE 300

XbeeAPI::RxMessage::RxMessage()
{
  payload[PACKET_SIZE];
  terminated = false;
}

bool XbeeAPI::RxMessage::hasTerminated()
{
  return terminated;
}

unsigned char XbeeAPI::RxMessage::appendPayload(unsigned char* packet)
{
  if(terminated){
    return 0x00;
  }

  unsigned char len = packet[1]-13;

  char temp[len];
  int pos = 0;
  for(int i = 16; i < packet[1]; i++){
    if(packet[pos] == '!'){
      terminated = true;
      len = pos+1;
      break;
    }
    temp[pos] = packet[i]; 
  }
  strncpy((char*)payload, temp, len);

  if(terminated){
    //const char* heartbeat = "HB#:!";
    if(strstr((char*)payload,"HB#:!")) {
      return 1;
    }
  }else{
    return 0;
  }

}

unsigned char* XbeeAPI::RxMessage::getPayload()
{
  if(terminated)
    return payload;
  else
    return 0;
}

// ?12,12,12,12,13,14,15,16,16,21,23,21,34,15,45,65,43,67,85,34,23,24,25,26!