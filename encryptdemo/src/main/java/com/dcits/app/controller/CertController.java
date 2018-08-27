package com.dcits.app.controller;

import com.dcits.app.service.CertService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/cert")
public class CertController {
    @Autowired
    private CertService certService;

    @PostMapping("/getAuditDetailLce")
    public void getAuditDetailLce(@RequestParam("id") String id){
        certService.getAuditDetailLce(id);
    }
}
