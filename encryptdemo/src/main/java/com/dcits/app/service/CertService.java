package com.dcits.app.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.dcits.app.dao.CertDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Service
public class CertService {
  @Autowired private CertDao certDao;

  @RequestMapping("")
  public String getAuditDetailLce(String id) {
    Map map = certDao.getAuditDetailLce(id);
    System.out.println(map);
    return JSON.toJSONString(map, SerializerFeature.WriteDateUseDateFormat);
  }
}
