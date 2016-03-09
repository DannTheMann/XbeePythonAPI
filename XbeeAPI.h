/*
	XbeeAPI
*/
#ifndef XbeeAPI_h
#define XbeeAPI_h

#include "Arduino.h"

class XbeeAPI
{
  public:
  	// public methods
    XbeeAPI(Serial serialPort, int pin, unsigned char* name);
    uint8_t sendMessage();
    bool responseReady();
    String getResponse();
  private:
  	// Private methods
  	int produceFrame();
  	void poll();
  	bool validatePacket(char* packet);
  	void escape(char* packet);
  	void unescape(char* packet);

  	// Fields
  	RxMessage message;
  	TxStatus txstatus;
  	Serial serial;
    unsigned char* name;
  	class TxStatus
  	{
  	public:
  		TxStatus(unsigned char* packet);
  		bool wasSuccessful();
  		uint8_t  getDeliveryStatus();
   	private:
   		uint8_t delivery;
  	};
  	class RxMessage
  	{
  	public:
  		RxMessage();
  		bool hasTerminated();
  		unsigned char appendPayload(unsigned char* packet);
  		unsigned char* getPayload();
  	private:
  		uint8_t frameID;
  		bool terminated;
  		char[] payload; 
    };
  	
};

#endif