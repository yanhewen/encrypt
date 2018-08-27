package com.dcits.app;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class GenerateCert {
    public void generateCert(HttpServletRequest request, HttpServletResponse response){
        String id = request.getParameter("id");
        String type = request.getParameter("type");

    }
}
