package com.enterprisex;

public class TLVEntry {

	int Type;
	int Length;
	String Value;

	@Override
	public String toString() {
		return "TLVEntry [Type=" + Type + ", Length=" + Length + ", Value=" + Value + "]";
	}
	
}
