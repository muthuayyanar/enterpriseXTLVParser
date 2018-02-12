package com.enterprisex;

import java.util.Arrays;

public class TLVReader {

	private byte[] _input;
	private TLV _decoded;

	public TLVReader(byte[] input, TLV decoded) {
		this._input = input;
		this._decoded = decoded;
	}

	public void parseHeader() {		
		//parse version
		int majorVersion = _input[3];
		int minorversion = _input[4];
		_decoded.get_header().set_majorVersion(majorVersion);
		_decoded.get_header().set_minorVersion(minorversion);
		//parse headerLength
		int headerLengthLength = _input[6]|_input[7];
		_decoded.get_header().set_headerLength(headerLengthLength);
		int headerLength = 0, startIndex=0, endIndex = 0;
		for(int i=0;i<headerLengthLength;i++) {
			headerLength <<= 8;
			headerLength |= _input[8+i];
			startIndex = 8+1+i;
		}
		endIndex = headerLength;
		_decoded.get_header().set_headerLength(headerLength);
		
		//parse signerID
		int signerIDTag = _input[++startIndex];
		int signerID = _input[++startIndex]|_input[++startIndex];
		_decoded.get_header().set_signerID(signerID);
		//parse other header entries		
		
		while(startIndex < endIndex) {
			TLVEntry entry = new TLVEntry();
			entry.Type = _input[startIndex];
			entry.Length = _input[++startIndex] | _input[++startIndex];
			if(entry.Length<0) {
				entry.Length = entry.Length*(-1); 
			}
			if(_input[++startIndex] != (Integer)(entry.Type+1)) 
			{
			byte[] value = new byte[entry.Length];
			System.arraycopy(_input, startIndex,value,0,entry.Length);
			entry.Value = new String(value);
			startIndex = startIndex+entry.Length;
			_decoded.get_header().AddEntry(entry);
			}
			else {
				entry.Value = "no value field";
				this._decoded.get_header().AddEntry(entry);
			}
			
		}
	}
	
	public void parseBody() {
		int start = _decoded.get_header().get_headerLength();
		int bodyType = _input[start];
		int bodyLengthLength = _input[++start] | _input[++start];
		int bodyLength = 0,startIndex = 0, endIndex = 0;
		for(int i=0;i<bodyLengthLength;i++) {
			bodyLength <<= 8;
			bodyLength |= _input[start+1+i];
			startIndex = start+1+1+i;
		}
		endIndex = bodyLength+start;
		_decoded.get_body().set_bodyLength(bodyLength);
		while(startIndex < endIndex) {
			TLVEntry entry = new TLVEntry();
			entry.Type = _input[startIndex];
			entry.Length = _input[++startIndex] | _input[++startIndex];
			if(entry.Length<0) {
				entry.Length = entry.Length*(-1); 
			}
			if(_input[++startIndex] != (Integer)(entry.Type+1)) 
			{
			byte[] value = new byte[entry.Length];
			System.arraycopy(_input, startIndex,value,0,entry.Length);
			entry.Value = new String(value);
			startIndex = startIndex+entry.Length;
			_decoded.get_body().AddEntry(entry);
			}
			else {
				entry.Value = "no value field";
				this._decoded.get_body().AddEntry(entry);
			}
			
		}
	}
}
