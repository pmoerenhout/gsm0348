package org.opentelecoms.gsm0348.impl.coders;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.opentelecoms.gsm0348.api.model.CardProfile;

public class CardProfileCoderTest {

	@Test
	public void test_no_security_card_profile_encoding() throws Exception {
		
		byte[] no_security_card_profile = new byte[7];
		
		CardProfile cardProfile = CardProfileCoder.encode(no_security_card_profile);
		
	    assertEquals(0, cardProfile.getKIC().getKeysetID());
	    assertEquals(0, cardProfile.getKID().getKeysetID());
	    assertEquals((byte)0x00, KICCoder.decode(cardProfile.getKIC()));
	    assertEquals((byte)0x00, KIDCoder.decode(cardProfile.getKID()));
	  }

}
