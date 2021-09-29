package com.senior.cyber.pki.dao;

import com.senior.cyber.metamodel.XmlUtility;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.File;
import java.io.IOException;

public class RepairProgram {
    public static void main(String[] args) throws IOException, SAXException, ParserConfigurationException, TransformerException {
        File folder = new File("pki-dao");
        File input = new File(folder, "src/main/resources/liquibase");
        File output = new File(folder, "src/main/resources/liquibase_output");
        XmlUtility.process(input, output);
    }
}
