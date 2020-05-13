package org.opentelecoms.gsm0348.impl.coders;

import org.junit.Assert;
import org.junit.Test;
import org.opentelecoms.gsm0348.api.model.AlgorithmImplementation;
import org.opentelecoms.gsm0348.api.model.CertificationAlgorithmMode;
import org.opentelecoms.gsm0348.api.model.CertificationMode;
import org.opentelecoms.gsm0348.api.model.KID;


public class KIDCoderTest {

  // No Security

  @Test
  public void test_kid_encode_no_security() throws Exception {
    final KID kid = KIDCoder.encode(CertificationMode.NO_SECURITY, (byte) 0x00);
    Assert.assertNull(kid.getAlgorithmImplementation());
    Assert.assertNull(kid.getCertificationAlgorithmMode());
    Assert.assertEquals((byte) 0x00, kid.getKeysetID());
  }

  // Cryptographic Checksum

  @Test
  public void test_kid_encode_cc_algorithm_known_both_entities() throws Exception {
    final KID kid = KIDCoder.encode(CertificationMode.CC, (byte) 0x10);
    Assert.assertEquals(AlgorithmImplementation.ALGORITHM_KNOWN_BY_BOTH_ENTITIES, kid.getAlgorithmImplementation());
    Assert.assertNull(kid.getCertificationAlgorithmMode());
    Assert.assertEquals((byte) 0x01, kid.getKeysetID());
  }

  @Test
  public void test_kid_encode_cc_des_cbc() throws Exception {
    final KID kid = KIDCoder.encode(CertificationMode.CC, (byte) 0x21);
    Assert.assertEquals(AlgorithmImplementation.DES, kid.getAlgorithmImplementation());
    Assert.assertEquals(CertificationAlgorithmMode.DES_CBC, kid.getCertificationAlgorithmMode());
    Assert.assertEquals((byte) 0x02, kid.getKeysetID());
  }

  @Test
  public void test_kid_encode_cc_aes_aes_cmac() throws Exception {
    final KID kid = KIDCoder.encode(CertificationMode.CC, (byte) 0x32);
    Assert.assertEquals(AlgorithmImplementation.AES, kid.getAlgorithmImplementation());
    Assert.assertEquals(CertificationAlgorithmMode.AES_CMAC, kid.getCertificationAlgorithmMode());
    Assert.assertEquals((byte) 0x03, kid.getKeysetID());
  }

  @Test
  public void test_kid_encode_cc_proprietary() throws Exception {
    final KID kid = KIDCoder.encode(CertificationMode.CC, (byte) 0x43);
    Assert.assertEquals(AlgorithmImplementation.PROPRIETARY_IMPLEMENTATIONS, kid.getAlgorithmImplementation());
    Assert.assertNull(kid.getCertificationAlgorithmMode());
    Assert.assertEquals((byte) 0x04, kid.getKeysetID());
  }

  @Test
  public void test_kid_encode_cc_triple_des_cbc_2_keys() throws Exception {
    final KID kid = KIDCoder.encode(CertificationMode.CC, (byte) 0x55);
    Assert.assertEquals(AlgorithmImplementation.DES, kid.getAlgorithmImplementation());
    Assert.assertEquals(CertificationAlgorithmMode.TRIPLE_DES_CBC_2_KEYS, kid.getCertificationAlgorithmMode());
    Assert.assertEquals((byte) 0x05, kid.getKeysetID());
  }

  @Test
  public void test_kid_encode_cc_triple_des_cbc_3_keys() throws Exception {
    final KID kid = KIDCoder.encode(CertificationMode.CC, (byte) 0x69);
    Assert.assertEquals(AlgorithmImplementation.DES, kid.getAlgorithmImplementation());
    Assert.assertEquals(CertificationAlgorithmMode.TRIPLE_DES_CBC_3_KEYS, kid.getCertificationAlgorithmMode());
    Assert.assertEquals((byte) 0x06, kid.getKeysetID());
  }

  // Redundancy Check

  @Test
  public void test_kid_encode_rc_algorithm_known_both_entities() throws Exception {
    final KID kid = KIDCoder.encode(CertificationMode.RC, (byte) 0x70);
    Assert.assertEquals(AlgorithmImplementation.ALGORITHM_KNOWN_BY_BOTH_ENTITIES, kid.getAlgorithmImplementation());
    Assert.assertNull(kid.getCertificationAlgorithmMode());
    Assert.assertEquals((byte) 0x7, kid.getKeysetID());
  }

  @Test
  public void test_kid_encode_rc_crc_16() throws Exception {
    final KID kid = KIDCoder.encode(CertificationMode.RC, (byte) 0x81);
    Assert.assertEquals(AlgorithmImplementation.CRC, kid.getAlgorithmImplementation());
    Assert.assertEquals(CertificationAlgorithmMode.CRC_16, kid.getCertificationAlgorithmMode());
    Assert.assertEquals((byte) 0x08, kid.getKeysetID());
  }

  @Test
  public void test_kid_encode_rc_crc_32() throws Exception {
    final KID kid = KIDCoder.encode(CertificationMode.RC, (byte) 0x95);
    Assert.assertEquals(AlgorithmImplementation.CRC, kid.getAlgorithmImplementation());
    Assert.assertEquals(CertificationAlgorithmMode.CRC_32, kid.getCertificationAlgorithmMode());
    Assert.assertEquals((byte) 0x09, kid.getKeysetID());
  }

  // Digital Signature

}