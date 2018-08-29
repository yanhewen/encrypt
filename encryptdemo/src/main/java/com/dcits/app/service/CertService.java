package com.dcits.app.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.dcits.app.dao.CertDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class CertService {
    @Autowired
    private CertDao certDao;

    public String getAuditDetailLce(String id) {
        Map map = certDao.getDetailLce(id);
        System.out.println(map);
        String s_map = JSON.toJSONString(map, SerializerFeature.WriteDateUseDateFormat);
        System.out.println(s_map);
        return s_map;
    }
}
