package com.enterprisex;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Iterator;
import java.nio.file.Path;

public class TLVParser {

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		System.out.println("Enterprise X - TLV Parser");
		File tlv = new File("TLV/SCFFile.tlv");
		Path path = Paths.get(tlv.getAbsolutePath());
		try {
			byte[] data = Files.readAllBytes(path);
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
