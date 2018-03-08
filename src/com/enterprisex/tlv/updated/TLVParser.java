package com.enterprisex.tlv.updated;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;

public class TLVParser {

	public static void main(String[] args) {
		System.out.println("Enterprise X - TLV Parser");
		Path path = Paths.get("c:/SCFFile.tlv");
		try {
			byte[] data = Files.readAllBytes(path);
			TLV test = new TLV();
			TLVReader reader = new TLVReader(data, test);
			reader.parseHeader();
			System.out.println(test.get_header());
			/*for (Iterator<TLVEntry> i = test.get_header().get_entries().iterator(); i.hasNext();) {
			    TLVEntry item = i.next();
			    System.out.println(item);
			}*/		
		} catch (IOException e) {
			System.out.println("Exception parsing tlv file : "+ e.getMessage());
		}	
	}
}
