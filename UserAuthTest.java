package com.primesoftcb.helper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import javax.naming.CommunicationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.modules.junit4.PowerMockRunnerDelegate;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.primesoftcb.saasimpl.SaasAPICallServiceImpl;

@RunWith(PowerMockRunner.class)
@PowerMockRunnerDelegate(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = { "classpath:*/test-applicationContext.xml" })
@PrepareForTest({UserAuthentication.class, InitialLdapContext.class, SaasAPICallServiceImpl.class})
public class UserAuthTest {
	
	@Mock
	ConnectionBrokerProperty connectionBrokerProperty;
	
	@InjectMocks
	UserAuthentication userAuthentication;
	
	
	@Before
	public void setUp() {
		MockitoAnnotations.initMocks(this);
	}

	@Test
	public void testCheckForCommunicationToAD() throws Exception {
		when(connectionBrokerProperty.getLdapHost()).thenReturn("ldap://localhost:386");
		
		InitialLdapContext mockLdapContext = PowerMockito.mock(InitialLdapContext.class);
		PowerMockito.doThrow(new NamingException("testing")).when(mockLdapContext).close();
		PowerMockito.whenNew(InitialLdapContext.class).withAnyArguments().thenReturn(mockLdapContext);
		assertTrue(userAuthentication.checkForCommunicationToAD());
		
		PowerMockito.whenNew(InitialLdapContext.class).withAnyArguments().thenThrow(new CommunicationException("Connection refused"));
		assertFalse(userAuthentication.checkForCommunicationToAD());
		
	}
	
	@Test
	public void testCheckForCommunicationToADNamingException() throws Exception {
		when(connectionBrokerProperty.getLdapHost()).thenReturn("ldap://localhost:386");
		PowerMockito.whenNew(InitialLdapContext.class).withAnyArguments().thenThrow(new NamingException("Unknown host"));
		assertFalse(userAuthentication.checkForCommunicationToAD());
	}

	@Test
	public void testCheckAuthenticationResponse() throws Exception {
	    
		when(connectionBrokerProperty.getLdapHost()).thenReturn("ldap://localhost:386");
	    HttpSession mockSession = mock(HttpSession.class);
	    
	    InitialLdapContext mockLdapContext = PowerMockito.mock(InitialLdapContext.class);
	    PowerMockito.whenNew(InitialLdapContext.class).withAnyArguments().thenReturn(mockLdapContext);
	    
	    Attribute attribute = mock(Attribute.class);
	    when(attribute.get()).thenReturn("cc07cacc5d9dfa40a9fb3a4d50a152b0".getBytes());
	    
	    Attributes attributes = mock(Attributes.class);
	    NamingEnumeration attributesEnumeration = mock(NamingEnumeration.class);
	    when(attributesEnumeration.hasMore()).thenAnswer(new Answer<Boolean>() {
	    	private int count = 1;
	    	
	    	@Override
	    	public Boolean answer(InvocationOnMock invocation) throws Throwable {
	    		if(count == 1){
	    			count++;
	    			return Boolean.TRUE;
	    		}
	    		else {
	    			return Boolean.FALSE;	
	    		}
	    		
	    	}
		});
	    when(attributesEnumeration.next()).thenReturn(attribute);
	    
	    when(attributes.getAll()).thenReturn(attributesEnumeration);
	    when(attributes.get("objectGUID")).thenReturn(attribute);

	    SearchResult searchResult = mock(SearchResult.class);
	    when(searchResult.getAttributes()).thenReturn(attributes);
	    
	    NamingEnumeration<SearchResult> nammingEnumeration = mock(NamingEnumeration.class);
	    when(nammingEnumeration.hasMoreElements()).thenAnswer(new Answer<Boolean>() {
	    	private int count = 1;
	    	
	    	@Override
	    	public Boolean answer(InvocationOnMock invocation) throws Throwable {
	    		if(count == 1){
	    			count++;
	    			return Boolean.TRUE;
	    		}
	    		else {
	    			return Boolean.FALSE;	
	    		}
	    		
	    	}
		});
	    when(nammingEnumeration.next()).thenReturn(searchResult);
	    
	    Map<String,  Map<String, String>> userEntitlementsList = new HashMap<String,  Map<String, String>>();
	    
	    SaasAPICallServiceImpl mockSaasAPICallServiceImpl = PowerMockito.mock(SaasAPICallServiceImpl.class);
	    when(mockSaasAPICallServiceImpl.getSAASUserEntitlementsDetails(anyString())).thenReturn(userEntitlementsList);
	    PowerMockito.whenNew(SaasAPICallServiceImpl.class).withNoArguments().thenReturn(mockSaasAPICallServiceImpl);
	    
	    
	    //PowerMockito.when(mockLdapContext.search(anyString(), anyString(), Mockito.any(SearchControls.class))).thenReturn(nammingEnumeration);
	    PowerMockito.doReturn(nammingEnumeration).when(mockLdapContext).search(anyString(), anyString(), Mockito.any(SearchControls.class));
	    String result = userAuthentication.checkAuthenticationResponse("Directory Manager", "password", "example.com", mockSession);
	    assertEquals(BrokerConstants.OPERATION_SUCCESS, result);
	    
	    //////////////
	    result = userAuthentication.checkAuthenticationResponse("Directory Manager", "password", "example", mockSession);
	    assertEquals(BrokerConstants.OPERATION_SUCCESS, result);
	    
	    //////
	    PowerMockito.doThrow(new NamingException("Unknown host")).when(mockLdapContext).search(anyString(), anyString(), Mockito.any(SearchControls.class));
	    result = userAuthentication.checkAuthenticationResponse("Directory Manager", "password", "example", mockSession);
	    assertEquals(BrokerConstants.OPERATION_SUCCESS, result);
	    
    	//////
//	    PowerMockito.doReturn(null).when(mockLdapContext).search(anyString(), anyString(), Mockito.any(SearchControls.class));
//	    result = userAuthentication.checkAuthenticationResponse("Directory Manager", "password", "example", mockSession);
//	    assertEquals(BrokerConstants.OPERATION_SUCCESS, result);
	    
	    ////////
	    NamingException unknownHostException = new NamingException("Unknown host");
	    PowerMockito.whenNew(InitialLdapContext.class).withAnyArguments().thenThrow(unknownHostException);
	    result = userAuthentication.checkAuthenticationResponse("Directory Manager", "password", "example", mockSession);
	    assertEquals(BrokerConstants.OPERATION_FAILURE, result);
	}
	
	@Test
	public void testCheckAuthenticationResponseForAuthenticationFailurePswExpired() throws Exception {
	    
		when(connectionBrokerProperty.getLdapHost()).thenReturn("ldap://localhost:386");
	    HttpSession mockSession = mock(HttpSession.class);
	    
	    InitialLdapContext mockLdapContext = PowerMockito.mock(InitialLdapContext.class);
	    PowerMockito.whenNew(InitialLdapContext.class).withAnyArguments().thenReturn(mockLdapContext);
	    
	    Attribute attribute = mock(Attribute.class);
	    when(attribute.get()).thenReturn("cc07cacc5d9dfa40a9fb3a4d50a172b0".getBytes());
	    
	    Attributes attributes = mock(Attributes.class);
	    when(attributes.get("objectGUID")).thenReturn(attribute);

	    SearchResult searchResult = mock(SearchResult.class);
	    when(searchResult.getAttributes()).thenReturn(attributes);
	    
	    NamingEnumeration<SearchResult> nammingEnumeration = mock(NamingEnumeration.class);
	    when(nammingEnumeration.hasMore()).thenReturn(true);
	    when(nammingEnumeration.next()).thenReturn(searchResult);
	    
	    Map<String,  Map<String, String>> userEntitlementsList = new HashMap<String,  Map<String, String>>();
	    
	    SaasAPICallServiceImpl mockSaasAPICallServiceImpl = PowerMockito.mock(SaasAPICallServiceImpl.class);
	    when(mockSaasAPICallServiceImpl.getSAASUserEntitlementsDetails(anyString())).thenReturn(userEntitlementsList);
	    PowerMockito.whenNew(SaasAPICallServiceImpl.class).withNoArguments().thenReturn(mockSaasAPICallServiceImpl);
	    
	    
	    ////////
	    NamingException passwordExpiryException = new NamingException("AcceptSecurityContext error, data 532, v893");
	    PowerMockito.whenNew(InitialLdapContext.class).withAnyArguments().thenThrow(passwordExpiryException);
	    String result = userAuthentication.checkAuthenticationResponse("Directory Manager", "password", "example", mockSession);
	    assertEquals(BrokerConstants.PASSWORD_EXPIRED, result);
	}

	@Test
	public void testCheckAuthenticationResponseForAuthenticationFailureAccountLocked() throws Exception {
	    
		when(connectionBrokerProperty.getLdapHost()).thenReturn("ldap://localhost:386");
	    HttpSession mockSession = mock(HttpSession.class);
	    
	    InitialLdapContext mockLdapContext = PowerMockito.mock(InitialLdapContext.class);
	    PowerMockito.whenNew(InitialLdapContext.class).withAnyArguments().thenReturn(mockLdapContext);
	    
	    Attribute attribute = mock(Attribute.class);
	    when(attribute.get()).thenReturn("cc07cacc5d9dfa40a9fb3a4d50a172b0".getBytes());
	    
	    Attributes attributes = mock(Attributes.class);
	    when(attributes.get("objectGUID")).thenReturn(attribute);

	    SearchResult searchResult = mock(SearchResult.class);
	    when(searchResult.getAttributes()).thenReturn(attributes);
	    
	    NamingEnumeration<SearchResult> nammingEnumeration = mock(NamingEnumeration.class);
	    when(nammingEnumeration.hasMore()).thenReturn(true);
	    when(nammingEnumeration.next()).thenReturn(searchResult);
	    
	    Map<String,  Map<String, String>> userEntitlementsList = new HashMap<String,  Map<String, String>>();
	    
	    SaasAPICallServiceImpl mockSaasAPICallServiceImpl = PowerMockito.mock(SaasAPICallServiceImpl.class);
	    when(mockSaasAPICallServiceImpl.getSAASUserEntitlementsDetails(anyString())).thenReturn(userEntitlementsList);
	    PowerMockito.whenNew(SaasAPICallServiceImpl.class).withNoArguments().thenReturn(mockSaasAPICallServiceImpl);
	    
	    NamingException accountLockedException = new NamingException("AcceptSecurityContext error, data 775, v893");
	    PowerMockito.whenNew(InitialLdapContext.class).withAnyArguments().thenThrow(accountLockedException);
	    String result = userAuthentication.checkAuthenticationResponse("Directory Manager", "password", "example", mockSession);
	    assertEquals(BrokerConstants.ACCOUNT_LOCKED, result);
	}

	@Test
	public void testUpdatePasswordOperationFailure() throws Exception {
		when(connectionBrokerProperty.getLdapHost()).thenReturn("ldap://localhost:386");
		when(connectionBrokerProperty.getLdapAdminUsername()).thenReturn("admin");
		when(connectionBrokerProperty.getLdapAdminPassword()).thenReturn("secret@123");
	    
	    NamingException namingException = new NamingException("Unknown host");
	    PowerMockito.whenNew(InitialLdapContext.class).withAnyArguments().thenThrow(namingException);
	    
	    String result = userAuthentication.updatePassword("test_user", "Old_password@123", "New_password@123", "example.com");
	    assertEquals(BrokerConstants.OPERATION_FAILURE, result);

	}
	
	
	@Test
	public void testUpdatePasswordOperationSuccess() throws Exception {
		when(connectionBrokerProperty.getLdapHost()).thenReturn("ldap://localhost:386");
		when(connectionBrokerProperty.getLdapAdminUsername()).thenReturn("admin");
		when(connectionBrokerProperty.getLdapAdminPassword()).thenReturn("secret@123");
		
		Attribute resourceAttribute = mock(Attribute.class);
	    when(resourceAttribute.get()).thenReturn("cc07cacc5d9dfa40a9fb3a4d50a152b0".getBytes());
		
		NamingEnumeration attributeSetEnum = mock(NamingEnumeration.class);
	    when(attributeSetEnum.hasMore()).thenAnswer(new Answer<Boolean>() {
	    	private int count = 1;
	    	
	    	@Override
	    	public Boolean answer(InvocationOnMock invocation) throws Throwable {
	    		if(count == 1){
	    			count++;
	    			return Boolean.TRUE;
	    		}
	    		else {
	    			return Boolean.FALSE;	
	    		}
	    		
	    	}
		});
	    when(attributeSetEnum.next()).thenReturn(resourceAttribute);

	    Attributes attributes = mock(Attributes.class);
	    when(attributes.getAll()).thenReturn(attributeSetEnum);

	    SearchResult searchResult = mock(SearchResult.class);
	    when(searchResult.getAttributes()).thenReturn(attributes);
	    
	    NamingEnumeration<SearchResult> nammingEnumeration = mock(NamingEnumeration.class);
	    when(nammingEnumeration.hasMoreElements()).thenAnswer(new Answer<Boolean>() {
	    	private int count = 1;
	    	
	    	@Override
	    	public Boolean answer(InvocationOnMock invocation) throws Throwable {
	    		if(count == 1){
	    			count++;
	    			return Boolean.TRUE;
	    		}
	    		else {
	    			return Boolean.FALSE;	
	    		}
	    		
	    	}
		});
	    when(nammingEnumeration.next()).thenReturn(searchResult);

		
	    InitialDirContext mockDirContext = PowerMockito.mock(InitialDirContext.class);
		PowerMockito.doReturn(nammingEnumeration).when(mockDirContext).search(anyString(), anyString(), Mockito.any(SearchControls.class));
		PowerMockito.whenNew(InitialDirContext.class).withAnyArguments().thenReturn(mockDirContext);
		
		String result = userAuthentication.updatePassword("test_user", "Old_password@123", "New_password@123", "example.com");
	    assertEquals(BrokerConstants.OPERATION_SUCCESS, result);
	    
	    PowerMockito.doThrow(new NamingException("LDAP: error code 19 - 00000775")).when(mockDirContext).close();
	    result = userAuthentication.updatePassword("test_user", "Old_password@123", "New_password@123", "example.com");
	    assertEquals(BrokerConstants.ACCOUNT_LOCKED, result);
	    
	    PowerMockito.doThrow(new NamingException("LDAP: error code 19 - 00000056")).when(mockDirContext).close();
	    result = userAuthentication.updatePassword("test_user", "Old_password@123", "New_password@123", "example.com");
	    assertEquals(BrokerConstants.OPERATION_FAILURE, result);
	    
	    PowerMockito.doThrow(new NamingException("LDAP: error code 19 - 00000775")).when(mockDirContext).search(anyString(), anyString(), Mockito.any(SearchControls.class));
	    result = userAuthentication.updatePassword("test_user", "Old_password@123", "New_password@123", "example.com");
	    assertEquals(BrokerConstants.OPERATION_FAILURE, result);
	}
}

