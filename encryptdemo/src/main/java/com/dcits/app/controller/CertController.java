package com.dcits.app.controller;

import com.dcits.app.service.CertService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/cert")
public class CertController {
    @Autowired
    private CertService certService;

    @PostMapping("/getAuditDetailLce")
    public void getAuditDetailLce() {
        String id = "cf491366-5c82-442a-93e5-b3fba0370c5a";
        certService.getAuditDetailLce(id);
    }
}
