package com.enterprisex;
import java.util.*;
public class TLVHeader {
	
	public TLVHeader() {
		this._entries = new ArrayList<TLVEntry>();
	}
	
	@Override
	public String toString() {
		return "Version\t" + _majorVersion + "." + _minorVersion + "\nHeaderLength\t"  + _headerLength + "\nSigner ID\t" + _signerID + "\n" + _entries + "]";
	}

	private int _majorVersion;
	private int _minorVersion;
	private int _headerLength;
	private int _signerID;
	
	private	List<TLVEntry> _entries;

	public List<TLVEntry> get_entries() {
		return _entries;
	}	
	
	public boolean AddEntry(TLVEntry entry) {
		_entries.add(entry);
		return true;
	}

	public int get_majorVersion() {
		return _majorVersion;
	}

	public void set_majorVersion(int _majorVersion) {
		this._majorVersion = _majorVersion;
	}

	public int get_minorVersion() {
		return _minorVersion;
	}

	public void set_minorVersion(int _minorVersion) {
		this._minorVersion = _minorVersion;
	}

	public int get_headerLength() {
		return _headerLength;
	}

	public void set_headerLength(int _headerLength) {
		this._headerLength = _headerLength;
	}

	public int get_signerID() {
		return _signerID;
	}

	public void set_signerID(int _signerID) {
		this._signerID = _signerID;
	}
}
