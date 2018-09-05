package com.zyc;

import org.json.JSONObject;
import org.json.XML;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Map;

public class NmapScan {
    /**
     * @apiNote nmap扫描接口（Linux环境下）
     *
     * @param ipRange 单个IP或者IP地址段
     *                例如： 192.168.5.1-255 或者 192.168.9.92
     * @param portRange 单个端口按照逗号分割，连续端口依“-”连接
     *                  例如： 22,3306,27017   1-9999
     * @param params nmap扫描的标准参数，请参考官方文档
     *
     * @return map 扫描结果依Map返回
     */
    public static Map<String, Object> scanNorm(String ipRange, String portRange, String ... params){
        String scanInfo = "nmap -oX - ";
        if (ipRange==null || ipRange.trim().length()==0) {
            throw new RuntimeException("IP地址或范围不能为空！");
        }
        if (portRange!=null && portRange.trim().length()>0) {
            scanInfo += " -p "+ portRange;
        }
        if (params!=null && params.length>0) {
            for (String string : params) {
                scanInfo += " "+string;
            }
        }
        scanInfo += " " + ipRange;
        StringBuffer result = new StringBuffer();
        execute(scanInfo, result);
        JSONObject jsonObject = XML.toJSONObject(result.toString());
        return jsonObject.toMap();
    }

    private static void execute(String scanInfo, StringBuffer result) {
        try {
            Process process = Runtime.getRuntime().exec(scanInfo);
            //----------读出标准缓冲区的内容-------------
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), "UTF-8"));
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line+"\n");
            }
            //等待调用nmap扫描完毕
            process.waitFor();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    /**
     * @apiNote nmap扫描接口（Linux环境下）
     *
     * @param ipRange 单个IP或者IP地址段
     *                例如： 192.168.5.1-255 或者 192.168.9.92
     * @param portRange 单个端口按照逗号分割，连续端口依“-”连接
     *                  例如： 22,3306,27017   1-9999
     * @param params nmap扫描的标准参数，请参考官方文档
     *
     * @return String 返回扫描结果原始内容
     */
    public static String scanReceiveXml(String ipRange, String portRange, String ... params){
        String scanInfo = "nmap -oX - ";
        if (ipRange==null || ipRange.trim().length()==0) {
            throw new RuntimeException("IP地址或范围不能为空！");
        }
        if (portRange!=null && portRange.trim().length()>0) {
            scanInfo += " -p "+ portRange;
        }
        if (params!=null && params.length>0) {
            for (String string : params) {
                scanInfo += " "+string;
            }
        }
        scanInfo += " " + ipRange;
        StringBuffer result = new StringBuffer();
        execute(scanInfo, result);
        return result.toString();
    }

}
