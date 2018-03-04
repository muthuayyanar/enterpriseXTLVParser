package com.enterprisex;

import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;

public class TLVParser {

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		System.out.println("Enterprise X - TLV Parser");
		
		String scfFile = "SCFFile.tlv";
		InputStream stream = TLVParser.class.getResourceAsStream(scfFile);
		
		try {
			//byte[] data = Files.readAllBytes(path);
			byte[] data = IOUtils.toByteArray(stream);
			TLV test = new TLV();
			TLVReader reader = new TLVReader(data, test);
			reader.parseHeader();
			System.out.println();
			reader.parseBody();
			System.out.println(test.get_header());
			System.out.println(test.get_body());
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
		
	}
}
