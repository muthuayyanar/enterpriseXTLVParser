package com.enterprisex.tlv.updated;

import java.nio.ByteBuffer;

public class TLVEntry {

	int Type;
	int Length;
	byte[] Value;
	TLVDataType datatype;

	public String trygetValue() {
		if (Value != null) {
			if (Value.length <= 4) {
				// all integers are 4 bytes in length. So, assuming anything under 4 byte is an
				// integer
				ByteBuffer wrapped = ByteBuffer.wrap(Value);
				return String.valueOf(wrapped.getInt());
			} else if (Value.length <= 8) {
				// long can be of length 8 bytes
				ByteBuffer wrapped = ByteBuffer.wrap(Value);
				return String.valueOf(wrapped.getLong());
			} else {
				// assuming everything above this is string..
				return new String(Value);
			}
		}
		else {
			return "";
		}
	}

	@Override
	public String toString() {
		return "TLVEntry [Type=" + Type + ", Length=" + Length + ", Value=" + trygetValue() + "]";
	}

}
