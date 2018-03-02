package com.enterprisex;

import java.util.ArrayList;
import java.util.List;

public class TLVBody {
	private	List<TLVRecord> _records;
	private int _bodyLength;
	
	public TLVBody() {
		this._records = new ArrayList<TLVRecord>();
	}
	
	@Override
	public String toString() {
		return "\n" + _records;
	}
	
	public int get_bodyLength() {
		return _bodyLength;
	}

	public List<TLVRecord> get_records() {
		return _records;
	}

	public void AddRecord(TLVRecord record) {
		_records.add(record);
	}

	public void set_bodyLength(int _bodyLength) {
		this._bodyLength = _bodyLength;
	}
}
