package com.enterprisex;

import java.util.ArrayList;
import java.util.List;

public class TLVBody {
	private	List<TLVEntry> _entries;
	private int _bodyLength;
	
	public TLVBody() {
		this._entries = new ArrayList<TLVEntry>();
	}
	
	@Override
	public String toString() {
		return "TLVBody _entries=" + _entries + "]";
	}
	public List<TLVEntry> get_entries() {
		return _entries;
	}	
	
	public boolean AddEntry(TLVEntry entry) {
		_entries.add(entry);
		return true;
	}
	public int get_bodyLength() {
		return _bodyLength;
	}

	public void set_bodyLength(int _bodyLength) {
		this._bodyLength = _bodyLength;
	}
}
