package ru.tapublog.lib.gsm0348.impl;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import ru.tapublog.lib.gsm0348.api.model.CardProfile;
import ru.tapublog.lib.gsm0348.api.model.CertificationMode;
import ru.tapublog.lib.gsm0348.api.model.SPI;
import ru.tapublog.lib.gsm0348.api.model.SecurityBytesType;
import ru.tapublog.lib.gsm0348.impl.coders.CommandSPICoder;
import ru.tapublog.lib.gsm0348.impl.coders.KICCoder;
import ru.tapublog.lib.gsm0348.impl.coders.KIDCoder;
import ru.tapublog.lib.gsm0348.impl.coders.ResponseSPICoder;

public class PacketBuilderImplTest {

  @Test
  public void test_no_rc_cc_ds() throws Exception {
    final PacketBuilderImpl packetBuilder = new PacketBuilderImpl(getCardProfileWithNoSignatureNoCiphering());
    final byte[] data = Hex.decode("A0A40000023F00A0A40000027F10A0A40000026f3CA0B2010405");
    final byte[] counter = Hex.decode("0102030405");
    final byte[] secured = packetBuilder.buildCommandPacket(data, counter, null, null);
    Assert.assertArrayEquals(Hex.decode("00280D10000000B00010010203040500A0A40000023F00A0A40000027F10A0A40000026F3CA0B2010405"), secured);
  }

  private CardProfile getCardProfileWithNoSignatureNoCiphering() throws CodingException {
    final CardProfile cardProfile = new CardProfile();
    cardProfile.setTAR(Hex.decode("B00010"));
    final SPI spi = new SPI();
    spi.setCommandSPI(CommandSPICoder.encode((byte) 0x10));
    spi.setResponseSPI(ResponseSPICoder.encode((byte) 0x00));
    cardProfile.setSPI(spi);
    cardProfile.setKIC(KICCoder.encode((byte) 0x00));
    cardProfile.setKID(KIDCoder.encode(CertificationMode.NO_SECURITY, (byte) 0x00));
    cardProfile.setSecurityBytesType(SecurityBytesType.NORMAL);
    return cardProfile;
  }
}