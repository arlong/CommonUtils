package com.common.utils;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.DisplayMetrics;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

/**
 * Created by yuliang.zhao on 2015/5/11.
 */
public class SignUtils {


    /**
     * 获取签名信息
     *
     * @param context
     * @return
     */
    private static Signature getSignatureInfo(Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            PackageInfo packageInfo = pm.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
            return packageInfo.signatures[0];
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 获取签名String
     *
     * @param context
     * @return
     */
    public static String getSignature(Context context) {
        Signature signature = getSignatureInfo(context);
        if (signature != null)
            return signature.toCharsString();
        return null;
    }

    /**
     * 获取签名证书配置信息
     *
     * @param context
     * @return
     */
    public static X509Certificate getSignCertificate(Context context) {
        Signature signature = getSignatureInfo(context);
        if (signature == null)
            return null;
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(signature.toByteArray()));
            String pubKey = cert.getPublicKey().toString();
            String signNumber = cert.getSerialNumber().toString();
            Log.e("sign", "signName:" + cert.getSigAlgName());
            Log.e("sign", "pubKey:" + pubKey);
            Log.e("sign", "signNumber:" + signNumber);
            Log.e("sign", "subjectDN:" + cert.getSubjectDN().toString());
            Log.e("sign", "version:" + cert.getVersion());

            return cert;
        } catch (CertificateException e) {
        }

        return null;
    }

    /**
     * 获取签名的MD5值
     *
     * @param context
     * @return
     */
    public static String getSignMD5(Context context) {
        Signature signature = getSignatureInfo(context);
        if (signature != null)
            return getStringMD5(signature.toByteArray());
        return null;
    }

    /**
     * 获取签名的SHA1值
     *
     * @param context
     * @return
     */
    public static String getSignSHA1(Context context) {
        Signature signature = getSignatureInfo(context);
        if (signature != null)
            return getStringSHA1(signature.toByteArray());
        return null;
    }

    /**
     * 获取签名的SHA256值
     *
     * @param context
     * @return
     */
    public static String getSignSHA256(Context context) {
        Signature signature = getSignatureInfo(context);
        if (signature != null)
            return getStringSHA256(signature.toByteArray());
        return null;
    }


    /**
     * 获取签名的MD5值
     *
     * @param bytes
     * @return
     */
    public static String getStringMD5(byte[] bytes) {
        try {
            byte[] data = MessageDigest.getInstance("MD5").digest(bytes);
            return getString(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 获取签名的SHA1值
     *
     * @param bytes
     * @return
     */
    public static String getStringSHA1(byte[] bytes) {
        try {
            byte[] data = MessageDigest.getInstance("SHA-1").digest(bytes);
            return getString(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 获取签名的SHA256值
     *
     * @param bytes
     * @return
     */
    public static String getStringSHA256(byte[] bytes) {
        try {
            byte[] data = MessageDigest.getInstance("SHA-256").digest(bytes);
            return getString(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    private static String getString(byte[] hash) {
        StringBuilder hex = new StringBuilder(hash.length * 2);
        for (byte b : hash) {
            if ((b & 0xFF) < 0x10)
                hex.append("0");
            hex.append(Integer.toHexString(b & 0xFF));
        }
        return hex.toString().toUpperCase(Locale.US);
    }

    /**
     * 获取未安装Apk的签名
     *
     * @param apkPath
     * @return
     */
    public static String getUnInstalledApkSignature(String apkPath) {
        String PATH_PackageParser = "android.content.pm.PackageParser";

        try {
            Class<?> pkgParserCls = Class.forName(PATH_PackageParser);
            Class<?>[] typeArgs = new Class[1];
            typeArgs[0] = String.class;
            Constructor<?> pkgParserCt = pkgParserCls.getConstructor(typeArgs);
            Object[] valueArgs = new Object[1];
            valueArgs[0] = apkPath;
            Object pkgParser = pkgParserCt.newInstance(valueArgs);

            DisplayMetrics metrics = new DisplayMetrics();
            metrics.setToDefaults();

            typeArgs = new Class[4];
            typeArgs[0] = File.class;
            typeArgs[1] = String.class;
            typeArgs[2] = DisplayMetrics.class;
            typeArgs[3] = Integer.TYPE;

            Method pkgParser_parsePackageMtd = pkgParserCls.getDeclaredMethod("parsePackage", typeArgs);
            valueArgs = new Object[4];
            valueArgs[0] = new File(apkPath);
            valueArgs[1] = apkPath;
            valueArgs[2] = metrics;
            valueArgs[3] = PackageManager.GET_SIGNATURES;
            Object pkgParserPkg = pkgParser_parsePackageMtd.invoke(pkgParser, valueArgs);

            typeArgs = new Class[2];
            typeArgs[0] = pkgParserPkg.getClass();
            typeArgs[1] = Integer.TYPE;

            Method pkgParser_collectCertificatesMtd = pkgParserCls.getDeclaredMethod("collectCertificates", typeArgs);
            valueArgs = new Object[2];
            valueArgs[0] = pkgParserPkg;
            valueArgs[1] = PackageManager.GET_SIGNATURES;
            pkgParser_collectCertificatesMtd.invoke(pkgParser, valueArgs);

            Field packageInfoFld = pkgParserPkg.getClass().getDeclaredField("mSignatures");
            Signature[] info = (Signature[]) packageInfoFld.get(pkgParserPkg);
            return info[0].toCharsString();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 获取已安装apk签名
     *
     * @param context
     * @param packageName
     * @return
     */
    public static String getInstalledApkSignature(Context context,
                                                  String packageName) {
        PackageManager pm = context.getPackageManager();
        List<PackageInfo> apps = pm
                .getInstalledPackages(PackageManager.GET_SIGNATURES);

        Iterator<PackageInfo> iter = apps.iterator();
        while (iter.hasNext()) {
            PackageInfo packageinfo = iter.next();
            String thisName = packageinfo.packageName;
            if (thisName.equals(packageName)) {
                return packageinfo.signatures[0].toCharsString();
            }
        }

        return null;
    }
}
