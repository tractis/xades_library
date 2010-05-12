// $Id: Verify.java 230957 2005-08-09 02:35:29Z hans $

//
// (C) Copyright 2005 VeriSign, Inc.  All Rights Reserved.
//
// VeriSign, Inc. shall have no responsibility, financial or
// otherwise, for any consequences arising out of the use of
// this material. The program material is provided on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. The user is responsible for determining
// any necessary third party rights or authorizations that may
// be required for the use of the materials. Users are advised 
// that they may need authorizations under certain patents from 
// Microsoft and IBM, or others. Please see notice.txt file. 
// VeriSign disclaims any obligation to notify the user of any 
// such third party rights.
//

import org.apache.tsik.domutil.DOMCursor;
import org.apache.tsik.domutil.DOMWriteCursor;
import org.apache.tsik.resource.ResourceFactory;
import org.apache.tsik.resource.XMLResource;
import org.apache.tsik.resource.XMLResource;
import org.apache.tsik.xmlsig.Signer;
import org.apache.tsik.xmlsig.Verifier;
import org.apache.tsik.xmlsig.HardwarePrivateKey;
import org.apache.tsik.xmlsig.tools.KeyConverter;
import org.apache.tsik.xpath.XPath;
import org.apache.tsik.xpath.XPathException;

import java.net.URL;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;

import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.PublicKey;

import java.util.Collection;
import java.util.Iterator;


import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class Verify 
{

    public static void main(String[] argv)
        throws Exception
    {
        FileInputStream fis = new FileInputStream(argv[0]);
        Document doc = Common.parseXMLDocument(fis);

        XMLResource xmlres = ResourceFactory.getXMLResource();
	RSAPublicKey publicKey = null;
	Certificate cert = null;
        if (argv.length > 1) {
	    FileInputStream istream = new FileInputStream(argv[1]);
	    try {
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		Collection c = cf.generateCertificates(istream);
		Iterator i = c.iterator();
		cert = (Certificate)i.next();
	    } catch (Exception e){
		istream = new FileInputStream(argv[1]);
		Document doc2 = xmlres.parseXML(istream, false);
		publicKey = (RSAPublicKey) 
		    KeyConverter.keyInfoToPublicKey(doc2, new XPath("/*"));
	    } finally {
		istream.close();
	    }
        }

        XPath xpath;
	String ns[] = {"ds", "http://www.w3.org/2000/09/xmldsig#"};
        if (argv.length > 2) {
            xpath = new XPath(argv[2], ns);
        } else {
            xpath = new XPath("//ds:Signature", ns);
        }
	Verifier verifier = new Verifier(doc, xpath);


	boolean result;
	if (publicKey != null){
	    result = verifier.verify(publicKey);
	} else if (cert != null){
	    result = verifier.verify(cert.getPublicKey());
	} else {
	    result = verifier.verify();
	}
	if (!result) System.out.println("Verify: " + result);
    }
}
