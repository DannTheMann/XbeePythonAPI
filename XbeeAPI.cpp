
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

#define MAX_TRANSMIT_RF_DATA 72 // MTU = 72 bytes
#define MAX_TRANSMISSION_ATTEMPTS 2

/**
*
* Fragments and sends a message to the coordinator
* Will return different ints based on results
* 0 = successful transmission
* 1 = failed on exceeding max retransmission attempts
* 2 = unknown error occurred 
* 3 = message exceeds fragmentation MTU limit
*/
uint8_t XbeeAPI::sendMessage(char* message)
{

   int len = strlen(message); // Len of message to send
   float framesNeededDivision = (len / 72.0f); // Work out the amount of frames required
   unsigned char framesNeeded = (unsigned char)ceil(framesNeededDivision); // smallest integral value not less than x

   // We can only send a maximum of 255 frames
   if(framesNeeded > 255){
      return 3; // Too large a message
   }


   // Internal buffer can store 202 bytes
   // Max payload is around 72 bytes for RF data
   unsigned char frame[150];
   unsigned char escapedFrame[200];
   unsigned char attempts = 0; // Total attempts made sending this frame

   for (int i = 0; i < framesNeeded; i++){

      if(txstatus != NULL){
        delete txstatus;
      }

      // returns the length of the escaped frame
      int escapedLen = produceFrame(escapedFrame, frame, (unsigned char*)message, len, i, framesNeeded);

      // Write out the contents of the array up to the length
      serial->write(escapedFrame, escapedLen);

      // Clear both char arrays with 0's
      memset(frame, 0, 150);
      memset(escapedFrame, 0, 200);
	    poll(2);
      //delay(250);

      // Checks whether the frame was received
      if (txstatus != NULL && txstatus->wasSuccessful()){
        attempts = 0;
        continue;

      // We reattempt sending the frame
      }else{
        i--;
        attempts++;

        // If we've tried x amount of times, report back error 1
        if(attempts >= MAX_TRANSMISSION_ATTEMPTS){
          return 1;
        }
        continue;
     }

   }

   // Returns whether the last frame was sent successfully
   return (txstatus != NULL && txstatus->wasSuccessful()) ? 0 : 2;

 }

bool XbeeAPI::responseReady()
{
  return true;
}

/*
* Returns the message payload as unsigned char*
*/
unsigned char* XbeeAPI::getResponse()
{
  return message->getPayload();
}

/**
* Produces the entire frame, including in escaped form
* returns the length of the escaped frame
*/
int XbeeAPI::produceFrame(unsigned char* escapedFrame, unsigned char* frame, unsigned char* message, int len, int id, unsigned char framesNeeded)
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
  	  //Broadcast Range
  	  frame[16] = 0x00;
  	  // RF Data
      frame[17] = id +'0'; // Unique Frame ID
      int length = (id+1)*MAX_TRANSMIT_RF_DATA;
      //bool final = false;
      if(framesNeeded == (id+1)){
        //final = true;
        frame[2] = len-(id * MAX_TRANSMIT_RF_DATA)+15;
		    length = len;
      }else{
		    frame[2] = MAX_TRANSMIT_RF_DATA+15;  
	    } 

      int k = 18; // Offset in packet for RF data
  	  int j = id * MAX_TRANSMIT_RF_DATA; // Work out which part of the message we're extracting
        for(; j < length; j++){
            frame[k++] = message[j];
            // If this is the final message, append '!' to signify final frame
            if(j == len-1 && framesNeeded == id+1){ //j == len-1
              frame[2]++;
              frame[k++] = '!';
              break;
            }
        }
	  
      unsigned char checksum = 0;
      for(int i = 3; i < k; i++){ 
          checksum+=frame[i];
      }
      // Checksum equals 0xFF - sum += offset 3 onwards
	    checksum = 0xFF-checksum;
      frame[k] = checksum;

      return escape(frame, escapedFrame);
  
}

#define INPUT_SIZE 200

bool XbeeAPI::poll(uint8_t timesToPoll)
{

    unsigned char input[INPUT_SIZE + 1]; // Total length of data expected, including + 1 for termination \0
    unsigned char packet[INPUT_SIZE + 1]; // Total length of data expected, including + 1 for termination \0

    // How many times we want to check for incoming data
    for(int i = 0; i < timesToPoll; i++){

      // Clear arrays with 0
      memset(input, 0, INPUT_SIZE+1);
      memset(packet, 0, INPUT_SIZE+1);
      delay(250);
      // Read in all data we can up to INPUT_SIZE and store in 'input'
      uint8_t size = serial->readBytes(input, INPUT_SIZE);
      input[size] = 0; // Final termination of array \0


      unsigned char pos = 0;
      unsigned char checkPacket = 0;   
      for(int i = 0; i < size; i++){
        if(input[i] == 0x7E){
          if(!checkPacket){
            checkPacket = 1;
          // If the packet is valid, we want to continue checking serial data for other packets
          }else if (validatePacket(packet)){
            memset(packet, 0, INPUT_SIZE); // Reset packet
            pos = 0;
            checkPacket++;
          // If invalid packet and not checking packet then break 
          }else{
            break;
          }
        }
        packet[pos++] = input[i];
      }

      if(checkPacket == 1){
        validatePacket(packet);
      }

      if(message != NULL && message->hasTerminated()){
        return true;
      }else{
        return false;
      }
  }
}

/*
* Will verify whether the packet is in a correct format
* and returns true or false
*/
bool XbeeAPI::validatePacket(unsigned char* packet){

      unsigned char output[INPUT_SIZE];

      unsigned char outputLen = unescape(packet, output);

      // First two bytes are guaranteed to be these
      // If they are not, invalid packet
      if(output[0] != 0x7E || output[1] != 0x00){
        return false;
      }

      // Work out the length of the payload from the packet
      unsigned char len = output[2];


      // The length calculated from the unescape method
      // vs len from packet
      if(len != outputLen-3){
        return false;
      }

      unsigned char checkSum = output[outputLen];
      unsigned char calculatedCheckSum = 0;
      for(int i=3;i<outputLen-1;i++){
        calculatedCheckSum+=output[i];
      }

      calculatedCheckSum = 0xFF - calculatedCheckSum;

      if(checkSum != calculatedCheckSum){
        return false;
      }

      unsigned char frameType = output[3];

      if(frameType == 0x10){ // RxPacket

        if(message == NULL || message->hasTerminated()){
          if(message != NULL){
            delete message;
          }
          message = new RxMessage();
        }
        unsigned char response = message->appendPayload(output);
        unsigned char* mes = message->getPayload();

        // Whether this was a heartbeat request
        // If so, respond and let the Hub know identity of device
        if(response == 1){
          char str[20];
          strcpy(str, "HB#:");
          strcat(str, name);
          strcat(str, "!");
          sendMessage(str);
          delete message;
        }
        

      }else if(frameType == 0x8B) {// TxStatus packet
        if(txstatus != NULL){
          delete txstatus;
        }
        txstatus = new TxStatus(output);
      }else{
        //serial->println(frameType, HEX);
        return false; // Invalid packet
      }



}

unsigned char XbeeAPI::unescape(unsigned char* packet, unsigned char* output)
{

  unsigned char len = INPUT_SIZE; // Worst case scenario, we know the maximum size of the array
  unsigned char index = 1;
  unsigned char out = 3;
  output[0] = packet[0];

  if ( packet[1] == 0x7D) {// The length has been escaped, so we need unescape and determine it
      len = packet[3] ^ 0x20; // Get the original length 
      index = 4;
  }else{
      len = packet[2];
      index = 3;
  }
  output[1] = 0x00;
  output[2] = len; 

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

  return out-1;

}

unsigned char XbeeAPI::escape(unsigned char* packet, unsigned char* output)
{
  
  unsigned char len = packet[2];
  unsigned char pos = 1;

  output[0] = 0x7E;
  // For every byte in frame
  for(int i = 1; i < (len+4); i++){
    // if byte equals the following escape it
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
  // return length of escaped frame
  return pos;

}


/*
* TxStatus
*/
XbeeAPI::TxStatus::TxStatus(unsigned char* packet)
{
  delivery = packet[7];
}

// Returns true if delivery was successful
bool XbeeAPI::TxStatus::wasSuccessful()
{
  return getDeliveryStatus();
}

// Returns value of delivery status
uint8_t XbeeAPI::TxStatus::getDeliveryStatus()
{
  return delivery;
}

/*
* RxMessage
*/
#define PACKET_SIZE 300

XbeeAPI::RxMessage::RxMessage()
{
  payload[PACKET_SIZE];
  terminated = false;
  packetLength = 0;
}

// Returns true if packet has been assembled
bool XbeeAPI::RxMessage::hasTerminated()
{
  return terminated;
}

// Returns length of packet
uint8_t XbeeAPI::RxMessage::length()
{
  return packetLength;
}

// Append to existing message contents
unsigned char XbeeAPI::RxMessage::appendPayload(unsigned char* packet)
{
  if(terminated){
    // Don't add to payload if the message has terminated
    return 0x00;
  }

  // Work out length of frame and how much to append by
  unsigned char len = packet[1]-13;

  char temp[len];
  int pos = 0;
  // Append to existing message
  for(int i = 16; i < packet[1]; i++){
    if(packet[pos] == '!'){
      terminated = true;
      len = pos+1;
      break;
    }
    temp[pos] = packet[i]; 
  }
  strncpy((char*)payload, temp, len);

  packetLength += len;

  if(terminated){
    //const char* heartbeat = "HB#:!";
    if(strstr((char*)payload,"HB#:!")) {
      return 1;
    }
  }else{
    return 0;
  }

}

// Returns payload
unsigned char* XbeeAPI::RxMessage::getPayload()
{
  if(terminated)
    return payload;
  else
    return 0;
}

// ?12,12,12,12,13,14,15,16,16,21,23,21,34,15,45,65,43,67,85,34,23,24,25,26!