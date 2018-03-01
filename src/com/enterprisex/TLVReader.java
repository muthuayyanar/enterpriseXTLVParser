package com.enterprisex;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

public class TLVReader {

	private byte[] _input;
	private TLV _decoded;

	public TLVReader(byte[] input, TLV decoded) {
		this._input = input;
		this._decoded = decoded;
	}

	public void parseHeader() {
		// parse version
		int majorVersion = _input[3];
		int minorversion = _input[4];
		_decoded.get_header().set_majorVersion(majorVersion);
		_decoded.get_header().set_minorVersion(minorversion);
		// parse headerLength
		int headerLengthLength = (int) ((_input[6] << 8) | (_input[7] & 0xFF));
		_decoded.get_header().set_headerLength(headerLengthLength);
		int headerLength = 0, startIndex = 0, endIndex = 0;
		for (int i = 0; i < headerLengthLength; i++) {
			headerLength <<= 8;
			headerLength |= _input[8 + i];
			startIndex = 8 + 1 + i;
		}
		endIndex = headerLength;
		_decoded.get_header().set_headerLength(headerLength);

		// parse signerID
		int signerIDTag = _input[++startIndex];
		int signerID = (int) ((_input[++startIndex] << 8) | (_input[++startIndex] & 0xFF));
		_decoded.get_header().set_signerID(signerID);
		// parse other header entries

		while (startIndex < endIndex) {
			TLVEntry entry = new TLVEntry();
			entry.Type = _input[startIndex];
			entry.Length = (int) ((_input[++startIndex] << 8) | (_input[++startIndex] & 0xFF));
			if (_input[++startIndex] != (Integer) (entry.Type + 1)) {
				byte[] value = new byte[entry.Length];
				System.arraycopy(_input, startIndex, value, 0, entry.Length);
				entry.Value = new String(value);
				startIndex = startIndex + entry.Length;
			} else {
				entry.Value = "no value field";
			}
			this._decoded.get_header().AddEntry(entry);
		}
	}

	public void parseBody() {
		int start = _decoded.get_header().get_headerLength();
		int bodyLength = this._input.length - start, startIndex = start, endIndex = startIndex+bodyLength;
		_decoded.get_body().set_bodyLength(bodyLength);

		while (startIndex < endIndex) {

			TLVRecord record = new TLVRecord();
			int recordLengthLength = (int) ((_input[++startIndex] << 8) | (_input[++startIndex] & 0xFF));
			int recordLength = 0;
			for (int i = 0; i < recordLengthLength; i++) {
				recordLength <<= 8;
				recordLength |= _input[++startIndex] & 0xFF;
			}
			record.set_recordLength(recordLength);

			int recordStartIndex = 0, recordEndIndex = 0;
			recordStartIndex = ++startIndex;
			//subtracting 3 bytes to exclude the Record length (type 1 byte, length 2 bytes and actual length)
			recordEndIndex = recordStartIndex + recordLength-1-2-recordLengthLength;
			while (recordStartIndex < recordEndIndex) 
			{
				TLVEntry entry = new TLVEntry();
				entry.Type = _input[recordStartIndex];
				entry.Length = (int) ((_input[++recordStartIndex] << 8) | (_input[++recordStartIndex] & 0xFF));
				if (_input[++recordStartIndex] != (Integer) (entry.Type + 1)) {
					if (entry.Type == 7) {
						entry.Value = "encrypted";
					} else if (entry.Type == 8) {
						entry.Value = "encrypted2";
					} else if (entry.Type == 9) {
						CertificateFactory certFactory = null;
						try {
							certFactory = CertificateFactory.getInstance("X.509");
						} catch (CertificateException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
						byte[] value = new byte[entry.Length];
						System.arraycopy(_input, recordStartIndex, value, 0, entry.Length);
						InputStream in = new ByteArrayInputStream(value);
						try {
							X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
							X500Principal principal = cert.getSubjectX500Principal();

							X500Name x500name = new X500Name(principal.getName());
							RDN cn = x500name.getRDNs(BCStyle.CN)[0];
							String cnVal = IETFUtils.valueToString(cn.getFirst().getValue());
							System.out.println("CN Value: " + cnVal);
						} catch (CertificateException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else {
						byte[] value = new byte[entry.Length];
						System.arraycopy(_input, recordStartIndex, value, 0, entry.Length);
						entry.Value = new String(value);
					}

					recordStartIndex = recordStartIndex + entry.Length;
				} else {
					entry.Value = "no value field";
				}
				record.Add(entry);
				startIndex = recordEndIndex;
			}
			
			_decoded.get_body().AddRecord(record);
		}
	}
}
