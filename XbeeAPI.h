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
    XbeeAPI(Serial serialPort);
    uint8_t sendMessage();
    bool responseReady();
    String getResponse();
  private:
  	// Private methods
  	uint8_t produceFrame();
  	uint8_t onSerialEvent();
  	bool validatePacket(char* packet);
  	void escape(char* packet);
  	void unescape(char* packet);

  	// Fields
  	RxMessage message;
  	TxStatus txstatus;
  	Serial serial;
  	class TxStatus
  	{
  	public:
  		TxStatus(String packet);
  		bool wasSuccessful();
  		uint8_t  getDeliveryStatus();
   	private:
   		uint8_t delivery;
  	}
  	class RxMessage
  	{
  	public:
  		RxMessage(String packet);
  		bool hasTerminated();
  		void appendPayload(String packet);
  		String getPayload();
  	private:
  		uint8_t frameID;
  		bool terminated;
  		char[] payload; 

  	}
};

#endif