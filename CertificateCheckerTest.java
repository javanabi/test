package com.primesoftcb.saasimpl;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.modules.junit4.PowerMockRunnerDelegate;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;


@RunWith(PowerMockRunner.class)
@PowerMockRunnerDelegate(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = { "classpath:*/test-applicationContext.xml" })
@PrepareForTest({CertificateChecker.class})
public class CertificateCheckerTest {
	
	private class MockX509Certiface extends X509Certificate {

		@Override
		public boolean hasUnsupportedCriticalExtension() {
			return false;
		}

		@Override
		public Set<String> getCriticalExtensionOIDs() {
			return null;
		}

		@Override
		public Set<String> getNonCriticalExtensionOIDs() {
			return null;
		}

		@Override
		public byte[] getExtensionValue(String oid) {
			return null;
		}

		@Override
		public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
			
		}

		@Override
		public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
		}

		@Override
		public int getVersion() {
			return 0;
		}

		@Override
		public BigInteger getSerialNumber() {
			return null;
		}

		@Override
		public Principal getIssuerDN() {
			return null;
		}

		@Override
		public Principal getSubjectDN() {
			return null;
		}

		@Override
		public Date getNotBefore() {
			return null;
		}

		@Override
		public Date getNotAfter() {
			return null;
		}

		@Override
		public byte[] getTBSCertificate() throws CertificateEncodingException {
			return null;
		}

		@Override
		public byte[] getSignature() {
			return null;
		}

		@Override
		public String getSigAlgName() {
			return null;
		}

		@Override
		public String getSigAlgOID() {
			return null;
		}

		@Override
		public byte[] getSigAlgParams() {
			return null;
		}

		@Override
		public boolean[] getIssuerUniqueID() {
			return null;
		}

		@Override
		public boolean[] getSubjectUniqueID() {
			return null;
		}

		@Override
		public boolean[] getKeyUsage() {
			return null;
		}

		@Override
		public int getBasicConstraints() {
			return 0;
		}

		@Override
		public byte[] getEncoded() throws CertificateEncodingException {
			return null;
		}

		@Override
		public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
				NoSuchProviderException, SignatureException {
		}

		@Override
		public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException,
				InvalidKeyException, NoSuchProviderException, SignatureException {
		}

		@Override
		public String toString() {
			return null;
		}

		@Override
		public PublicKey getPublicKey() {
			return null;
		}
		
	}
	
	
	@Test                                                                                                                   
	public void cerificateCheckTest() throws Exception {
		
		Certificate mockCertificate = new MockX509Certiface();
		
		Certificate[] certificates = new Certificate[1];
		certificates[0]= mockCertificate;
		
		HttpsURLConnection mockUrlConnection = PowerMockito.mock(HttpsURLConnection.class);
		PowerMockito.when(mockUrlConnection.getResponseCode()).thenReturn(HttpsURLConnection.HTTP_OK);
		PowerMockito.doReturn(certificates).when(mockUrlConnection).getServerCertificates();
		
		URL mockUrl = PowerMockito.mock(URL.class);
		PowerMockito.when(mockUrl.openConnection()).thenReturn(mockUrlConnection);
		PowerMockito.whenNew(URL.class).withAnyArguments().thenReturn(mockUrl);
		
		CertificateChecker mockCertificateChecker = new CertificateChecker();//mock(CertificateChecker.class);
		assertTrue(mockCertificateChecker.cerificateCheck("http://sample.com"));
		
		/////////////////////
		PowerMockito.when(mockUrlConnection.getResponseCode()).thenReturn(HttpsURLConnection.HTTP_BAD_REQUEST);
		assertFalse(mockCertificateChecker.cerificateCheck("http://sample.com"));
		
		
	}
	
	@Test                                                                                                                   
	public void cerificateCheckTestException() throws Exception {
		
		Certificate mockCertificate = new MockX509Certiface(){
			@Override
			public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
				throw new CertificateExpiredException("certificate expired");
			}
		};
		
		Certificate[] certificates = new Certificate[1];
		certificates[0]= mockCertificate;
		
		HttpsURLConnection mockUrlConnection = PowerMockito.mock(HttpsURLConnection.class);
		PowerMockito.when(mockUrlConnection.getResponseCode()).thenReturn(HttpsURLConnection.HTTP_OK);
		PowerMockito.doReturn(certificates).when(mockUrlConnection).getServerCertificates();
		
		URL mockUrl = PowerMockito.mock(URL.class);
		PowerMockito.when(mockUrl.openConnection()).thenReturn(mockUrlConnection);
		PowerMockito.whenNew(URL.class).withAnyArguments().thenReturn(mockUrl);
		
		CertificateChecker mockCertificateChecker = new CertificateChecker();//mock(CertificateChecker.class);
		assertFalse(mockCertificateChecker.cerificateCheck("http://sample.com"));
		
		///////////////
		mockCertificate = new MockX509Certiface(){
			@Override
			public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
				throw new CertificateNotYetValidException("certificate not yet valid exception");
			}
		};
		certificates[0]= mockCertificate;
		PowerMockito.doReturn(certificates).when(mockUrlConnection).getServerCertificates();
		assertFalse(mockCertificateChecker.cerificateCheck("http://sample.com"));
		
		/////////////////////
		IllegalStateException exception = new IllegalStateException("IllegalStateException");
		PowerMockito.doThrow(exception).when(mockUrlConnection).getServerCertificates();
		assertFalse(mockCertificateChecker.cerificateCheck("http://sample.com"));
		
		/////////////////////
		IOException exceptionIo = new IOException("IOException");
		PowerMockito.doThrow(exceptionIo).when(mockUrl).openConnection();
		assertFalse(mockCertificateChecker.cerificateCheck("http://sample.com"));
	}
}

