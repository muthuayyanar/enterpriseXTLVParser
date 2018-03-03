package com.enterprisex;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Iterator;

import org.apache.commons.io.IOUtils;

import java.nio.file.Path;

public class TLVParser {

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		System.out.println("Enterprise X - TLV Parser");
		File tlv = new File("TLV/SCFFile.tlv");
		Path path = Paths.get(tlv.getAbsolutePath());
		
		String resourceName = "SCFFile.tlv";
		//ClassLoader classLoader = TLVParser.class.getResourceAsStream(resourceName);
		//InputStream stream = classLoader.getResourceAsStream(resourceName);
		InputStream stream = TLVParser.class.getResourceAsStream(resourceName);
		
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
