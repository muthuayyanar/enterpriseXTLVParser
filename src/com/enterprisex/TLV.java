package com.enterprisex;

public class TLV {
	
	private TLVHeader _header;
	private TLVBody _body;
	
	public TLV() {
		this._header = new TLVHeader();
	}

	public TLVHeader get_header() {
		return _header;
	}

	public void set_header(TLVHeader _header) {
		this._header = _header;
	}

	public TLVBody get_body() {
		return _body;
	}

	public void set_body(TLVBody _body) {
		this._body = _body;
	}

}
