// $Id: Common.java 230957 2005-08-09 02:35:29Z hans $

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

import org.apache.tsik.resource.ResourceFactory;
import org.apache.tsik.resource.XMLResource;
import org.apache.tsik.xmlsig.Signer;
import org.apache.tsik.xmlsig.Verifier;
import org.apache.tsik.xpath.XPath;
import org.apache.tsik.xpath.XPathException;

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
import java.security.PrivateKey;

import org.apache.tsik.xmlsig.tools.KeyConverter; 

import java.util.Collection;
import java.util.Iterator;


import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class Common 
{
    static RSAPrivateKey privateKey = null;
    static RSAPublicKey publicKey = null;
    static RSAPublicKey oldPublicKey = null;

    public static RSAPrivateKey getPrivateKey()
    {
        return privateKey;
    }

    public static RSAPublicKey getPublicKey()
    {
        return publicKey;
    }

    public static RSAPublicKey getOldPublicKey()
    {
        return oldPublicKey;
    }

    protected static boolean setUp(String pfx) 
    {
        String sfx = "";
        try {
            XMLResource xmlres = ResourceFactory.getXMLResource();

            FileInputStream istream = new FileInputStream(pfx + "priv.xml");
            Document doc = xmlres.parseXML(istream, false);
            privateKey = (RSAPrivateKey) 
                KeyConverter.keyInfoToPrivateKey(doc, new XPath("/*"));
            istream.close();        

            istream = new FileInputStream(pfx + "pub.xml");
            doc = xmlres.parseXML(istream, false);
            publicKey = (RSAPublicKey) 
                KeyConverter.keyInfoToPublicKey(doc, new XPath("/*"));
            istream.close();

            istream = new FileInputStream(pfx + "old_pub.xml");
            doc = xmlres.parseXML(istream, false);
            oldPublicKey = (RSAPublicKey) 
                KeyConverter.keyInfoToPublicKey(doc, new XPath("/*"));
            istream.close();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    
    public static Signer sign1(String inFileName,
                                PrivateKey privateKey,
                                PublicKey publicKey,
                                X509Certificate cert) throws Exception {
        FileInputStream fis = new FileInputStream(new File(inFileName));
        Document doc = parseXMLDocument(fis);

        Signer signer = null;
        if (cert != null){
            signer = new Signer(doc, privateKey, cert);
        } else if (publicKey != null){
            signer = new Signer(doc, privateKey, publicKey);
        } else {
            signer = new Signer(doc, privateKey);
        }
        return signer;
    }


    public static Document sign2(Signer signer,
                              String type,
                              String outFileName) throws Exception {
        Document d;
        if (type.equals("")){
            d = signer.sign();
        } else {
            XPath xpath = new XPath(type);
            d = signer.sign(xpath);
        }
        publishXMLDocument(d.getDocumentElement(), 
                           new FileOutputStream(new File(outFileName)));
        return d;
    }


    public static boolean verify(String inFileName,
                                  String signatureLocation,
                                  PublicKey publicKey,
                                  boolean mustHavePublicKey,
                                  boolean mustHaveCert) throws Exception {
        FileInputStream fis = new FileInputStream(new File(inFileName));
        Document doc = parseXMLDocument(fis);
        
        String ns[] = {"ds", "http://www.w3.org/2000/09/xmldsig#",
                       "s2", "http://ns.s2ml.org/s2ml",
                       "SOAP-ENV",
                       "http://schemas.xmlsoap.org/soap/envelope/",
                       "EMS", "http://ems.verisign.com/2001/05/ems-s2ml#"};
        XPath xpath = new XPath(signatureLocation, ns);
        Verifier verifier = new Verifier(doc, xpath);
        
        PublicKey pubKey = publicKey;
        if (mustHavePublicKey){
            pubKey = verifier.getVerifyingKey();
            if (pubKey == null) {
                System.err.println("Cannot find public key");
                return false;
            }
        }
        
        if (mustHaveCert) {
            X509Certificate cert = verifier.getCertificate();
            if (cert == null) {
                System.err.println("Cannot find certificate");
                return false;
            }
        }
        return verifier.verify(pubKey);
    }

    static public Document parseXMLDocument(InputStream is) throws IOException{
        XMLResource xmlres = ResourceFactory.getXMLResource();
        return xmlres.parseXML(is, false);
    }

    static void publishXMLDocument(Element element, OutputStream out) 
        throws IOException
    {
        XMLResource xml = ResourceFactory.getXMLResource(); 
        xml.publish(element, out);
    }
}
