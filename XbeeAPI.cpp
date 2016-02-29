/*
  Morse.cpp - Library for flashing Morse code.
  Created by David A. Mellis, November 2, 2007.
  Released into the public domain.
*/

#include "Arduino.h"
#include "XbeeAPI.h"

/*
* XbeeAPI
*/

XbeeAPI::XbeeAPI(Serial serial)
{
  serial.begin(9600);
  serial.setTimeout(1000);
}

uint8_t XbeeAPI::sendMessage()
{
   return 0;
}

bool XbeeAPI::responseReady()
{
  return true;
}

String XbeeAPI::getResponse()
{
  return null;
}

uint8_t XbeeAPI::produceFrame()
{
  
}

#define INPUT_SIZE 100

uint8_t XbeeAPI::readSerial()
{
  for(;;){

    unsigned char input[INPUT_SIZE + 1]; // Total length of data expected, including + 1 for termination \0
    byte size = Serial.readBytes(input, INPUT_SIZE);
    input[size] = 0; // Final termination of array \0

    unsigned char* packet = strtok(input, 0x7E);


    while(packet != 0){

      if (validatePacket(packet)){
        packet = strtok(input, 0x7E);
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
}

bool XbeeAPI::validatePacket(unsigned char* packet){

      unescape(packet);

      if(packet[0] != 0x00)
        return false;

      unsigned char len = packet[1];
      unsigned char actualLen = strlen(packet);

      if(len != actualLen-3)
        return false;

      unsigned char checkSum = packet[len-1];
      unsigned char calculatedCheckSum = 0;

      for(int i=2;i<actualLen;i++){
        calculatedCheckSum+=packet[i];
      }

      if(checksum != 0xFF){
        return false;
      }

      unsigned char frameType = packet[2];

      if(frameType == 0x10){ // RxPacket

        if(message != null){
          char payload[(len-12)];
          memcpy(payload, );
          message.appendPayload(payload)
        }

      }else if(frameType == 0x8B) {// TxStatus packet

      }else{
        return false; // Invalid packet
      }



}

void XbeeAPI::onSerialEvent(){
    String packet = serial.readString();
    serial.flush();
}

void XbeeAPI::unescape(unsigned char* packet)
{
  // unescape frame
  bool skipNextChar = false;
  for( int i = 0; i < strlen(packet) ; i++){
    if(skip){
      skip = false;
      continue;
    }

    if(packet[i] == 0x7D){
      curr = input[i+1] ^ 0x20;
      skip = true;
    }
  }
}

void XbeeAPI::escape(unsigned char* packet)
{
  
}

/*
* TxStatus
*/
TxStatus::TxStatus(String packet)
{
  delivery = packet.charAt(8);
}

bool TxStatus::wasSuccessful()
{
  return getDeliveryStatus();
}

uint8_t TxStatus::getDeliveryStatus()
{
  return delivery == 0;
}


/*
* RxMessage
*/
RxMessage::RxMessage(String packet)
{
  payload = packet.substring(15, packet.length()-1); // Get the payload from the frame
}

bool RxMessage::hasTerminated()
{
  return terminated;
}

void RxMessage::appendPayload(String packet)
{
  if(terminated)
    return;

  payload += packet.substring(15, packet.length()-1); // Get the payload from the frame

  if(payload.charAt(payload.length) == '!'){
    terminated = true;
  }

  payload.replace('!','');
}