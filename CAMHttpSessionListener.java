package com.primesoft.admin.util;

import java.util.HashMap;
import java.util.Properties;

import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import com.primesoft.admin.helper.AdminPropertyHelper;

public class CAMHttpSessionListener implements HttpSessionListener {

	String sessionTimeout;

	@Override
	public void sessionCreated(HttpSessionEvent event) {
		Properties properties = new Properties();
		AdminPropertyHelper adminPropertyHelper = new AdminPropertyHelper();
		try {
			HashMap<String, String> configProperty = adminPropertyHelper.getProperties();
			for (String key : configProperty.keySet()) {
				properties.setProperty(key, configProperty.get(key));
			}
			sessionTimeout = properties.getProperty("CAMSessionTimeoutMinutes");
		} catch (Exception e) {
		}
		event.getSession().setMaxInactiveInterval(Integer.parseInt(sessionTimeout) * 5);
	}

	@Override
	public void sessionDestroyed(HttpSessionEvent event) {
		// TODO Auto-generated method stub
		System.out.println("sessionDestroyed");

	}
}
