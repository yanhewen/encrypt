package com.dcits.app.dao;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

import java.util.Map;

@Mapper
@Repository
public interface CertDao {
    Map<String, Object> getDetailLce(@Param("id") String id);
}
