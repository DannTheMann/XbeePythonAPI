/*
	XbeeAPI
*/
#ifndef XbeeAPI_h
#define XbeeAPI_h

#include <Arduino.h>
#include <HardwareSerial.h>

class XbeeAPI
{
  public:
  	// public methods
    XbeeAPI(HardwareSerial * serialPort, int pin, const char* name);
    uint8_t sendMessage(char* message);
    bool responseReady();
    bool poll(uint8_t timesToPoll);
    unsigned char* getResponse();
  private:
  	// Private methods
  	int produceFrame(unsigned char* escapedFrame, unsigned char* frame, unsigned char* message, int len, int id, unsigned char framesNeeded);
  	bool validatePacket(unsigned char* packet);
  	unsigned char escape(unsigned char* packet, unsigned char* output);
  	unsigned char unescape(unsigned char* packet, unsigned char* output);

  	// Fields
    public:
  	class TxStatus
  	{
  	public:
  		TxStatus(unsigned char* packet);
  		bool wasSuccessful();
  		uint8_t  getDeliveryStatus();
   	private:
   		uint8_t delivery;
  	};

    public:
  	class RxMessage
  	{
  	public:
  		RxMessage();
  		bool hasTerminated();
  		unsigned char appendPayload(unsigned char* packet);
  		unsigned char* getPayload();
      uint8_t length();
  	private:
  		uint8_t packetLength;
  		bool terminated;
  		unsigned char *payload; 
    };

  private:
    RxMessage *message;
    TxStatus *txstatus;
    HardwareSerial *serial;
    const char* name;
  	
};

#endif