package com.enterprisex;

import java.util.ArrayList;
import java.util.List;

public class TLVRecord {

	private int _recordLength;
	private List<TLVEntry> _entries;

	public TLVRecord() {
		_entries = new ArrayList<TLVEntry>();
	}
	
	public int get_recordLength() {
		return _recordLength;
	}

	public void set_recordLength(int _recordLength) {
		this._recordLength = _recordLength;
	}

	public List<TLVEntry> get_entries() {
		return _entries;
	}

	public void Add(TLVEntry entry) {
		_entries.add(entry);
	}

	@Override
	public String toString() {
		return "\nRecord Length\t" + _recordLength  +"\n" + _entries;
		
	}
	
	
	
	
}
