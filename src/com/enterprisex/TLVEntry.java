package com.enterprisex;

public class TLVEntry {

	int Type;
	int Length;
	String Value;

	@Override
	public String toString() {
		return Type +"/t" + Length +"/t"+  Value ;
	}
	
}
