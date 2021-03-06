//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.3.2 
// See <a href="https://javaee.github.io/jaxb-v2/">https://javaee.github.io/jaxb-v2/</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2020.04.01 at 10:04:03 PM CEST 
//


package org.opentelecoms.gsm0348.api.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for ResponseSPI complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ResponseSPI"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;all&gt;
 *         &lt;element name="PoRProtocol" type="{org.opentelecoms.gsm0348}PoRProtocol"/&gt;
 *         &lt;element name="PoRMode" type="{org.opentelecoms.gsm0348}PoRMode"/&gt;
 *         &lt;element name="PoRCertificateMode" type="{org.opentelecoms.gsm0348}CertificationMode"/&gt;
 *         &lt;element name="Ciphered" type="{http://www.w3.org/2001/XMLSchema}boolean"/&gt;
 *       &lt;/all&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ResponseSPI", propOrder = {

})
public class ResponseSPI {

    @XmlElement(name = "PoRProtocol", required = true)
    @XmlSchemaType(name = "string")
    protected PoRProtocol poRProtocol;
    @XmlElement(name = "PoRMode", required = true)
    @XmlSchemaType(name = "string")
    protected PoRMode poRMode;
    @XmlElement(name = "PoRCertificateMode", required = true)
    @XmlSchemaType(name = "string")
    protected CertificationMode poRCertificateMode;
    @XmlElement(name = "Ciphered")
    protected boolean ciphered;

    /**
     * Gets the value of the poRProtocol property.
     * 
     * @return
     *     possible object is
     *     {@link PoRProtocol }
     *     
     */
    public PoRProtocol getPoRProtocol() {
        return poRProtocol;
    }

    /**
     * Sets the value of the poRProtocol property.
     * 
     * @param value
     *     allowed object is
     *     {@link PoRProtocol }
     *     
     */
    public void setPoRProtocol(PoRProtocol value) {
        this.poRProtocol = value;
    }

    /**
     * Gets the value of the poRMode property.
     * 
     * @return
     *     possible object is
     *     {@link PoRMode }
     *     
     */
    public PoRMode getPoRMode() {
        return poRMode;
    }

    /**
     * Sets the value of the poRMode property.
     * 
     * @param value
     *     allowed object is
     *     {@link PoRMode }
     *     
     */
    public void setPoRMode(PoRMode value) {
        this.poRMode = value;
    }

    /**
     * Gets the value of the poRCertificateMode property.
     * 
     * @return
     *     possible object is
     *     {@link CertificationMode }
     *     
     */
    public CertificationMode getPoRCertificateMode() {
        return poRCertificateMode;
    }

    /**
     * Sets the value of the poRCertificateMode property.
     * 
     * @param value
     *     allowed object is
     *     {@link CertificationMode }
     *     
     */
    public void setPoRCertificateMode(CertificationMode value) {
        this.poRCertificateMode = value;
    }

    /**
     * Gets the value of the ciphered property.
     * 
     */
    public boolean isCiphered() {
        return ciphered;
    }

    /**
     * Sets the value of the ciphered property.
     * 
     */
    public void setCiphered(boolean value) {
        this.ciphered = value;
    }

}
