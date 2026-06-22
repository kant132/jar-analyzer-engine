/*
 * GPLv3 License
 *
 * Copyright (c) 2022-2026 4ra1n (Jar Analyzer Team)
 *
 * This project is distributed under the GPLv3 license.
 *
 * https://github.com/jar-analyzer/jar-analyzer/blob/master/LICENSE
 */

package me.n1ar4.jar.analyzer.analyze.jaxrs.asm;

import me.n1ar4.jar.analyzer.analyze.jaxrs.JaxRsConstant;
import me.n1ar4.jar.analyzer.analyze.jaxrs.JaxRsMapping;
import me.n1ar4.jar.analyzer.analyze.jaxrs.JaxRsResource;
import me.n1ar4.jar.analyzer.core.reference.ClassReference;
import me.n1ar4.jar.analyzer.core.reference.MethodReference;
import me.n1ar4.jar.analyzer.engine.EngineConst;
import me.n1ar4.jar.analyzer.engine.utils.StringUtil;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.MethodVisitor;

import java.util.Map;

public class JaxRsMethodAdapter extends MethodVisitor {
    private final Map<MethodReference.Handle, MethodReference> methodMap;
    private final JaxRsResource resource;
    private final String name;
    private final String owner;
    private final String desc;

    private JaxRsMapping currentMapping;
    private JaxRsPathAnnoAdapter pathAnnoAdapter = null;

    public JaxRsMethodAdapter(String name, String descriptor, String owner,
                              int api, MethodVisitor methodVisitor,
                              JaxRsResource currentResource,
                              Map<MethodReference.Handle, MethodReference> methodMap) {
        super(api, methodVisitor);
        this.owner = owner;
        this.desc = descriptor;
        this.name = name;
        this.methodMap = methodMap;
        this.resource = currentResource;
    }

    @Override
    public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
        AnnotationVisitor av = super.visitAnnotation(descriptor, visible);

        boolean isHttpMethod = false;
        String httpMethod = null;

        if (descriptor.equals(JaxRsConstant.JAVAX_GET_ANNO) ||
                descriptor.equals(JaxRsConstant.JAKARTA_GET_ANNO)) {
            isHttpMethod = true;
            httpMethod = "GET";
        } else if (descriptor.equals(JaxRsConstant.JAVAX_POST_ANNO) ||
                descriptor.equals(JaxRsConstant.JAKARTA_POST_ANNO)) {
            isHttpMethod = true;
            httpMethod = "POST";
        } else if (descriptor.equals(JaxRsConstant.JAVAX_PUT_ANNO) ||
                descriptor.equals(JaxRsConstant.JAKARTA_PUT_ANNO)) {
            isHttpMethod = true;
            httpMethod = "PUT";
        } else if (descriptor.equals(JaxRsConstant.JAVAX_DELETE_ANNO) ||
                descriptor.equals(JaxRsConstant.JAKARTA_DELETE_ANNO)) {
            isHttpMethod = true;
            httpMethod = "DELETE";
        } else if (descriptor.equals(JaxRsConstant.JAVAX_PATCH_ANNO) ||
                descriptor.equals(JaxRsConstant.JAKARTA_PATCH_ANNO)) {
            isHttpMethod = true;
            httpMethod = "PATCH";
        } else if (descriptor.equals(JaxRsConstant.JAVAX_PATH_ANNO) ||
                descriptor.equals(JaxRsConstant.JAKARTA_PATH_ANNO)) {
            if (currentMapping == null) {
                currentMapping = new JaxRsMapping();
            }
            pathAnnoAdapter = new JaxRsPathAnnoAdapter(EngineConst.ASMVersion, av);
            av = pathAnnoAdapter;
        }

        if (isHttpMethod) {
            if (currentMapping == null) {
                currentMapping = new JaxRsMapping();
            }
            currentMapping.setHttpMethod(httpMethod);
        }

        return av;
    }

    @Override
    public void visitCode() {
        if (this.currentMapping != null) {
            currentMapping.setMethodName(new MethodReference.Handle(
                    new ClassReference.Handle(this.owner), this.name, this.desc));
            currentMapping.setMethodReference(methodMap.get(currentMapping.getMethodName()));

            String basePath = resource.getBasePath();
            String methodPath = null;

            if (pathAnnoAdapter != null) {
                if (!pathAnnoAdapter.getResults().isEmpty()) {
                    methodPath = pathAnnoAdapter.getResults().get(0);
                    if (!methodPath.startsWith("/")) {
                        methodPath = "/" + methodPath;
                    }
                    if (methodPath.endsWith("/") && methodPath.length() > 1) {
                        methodPath = methodPath.substring(0, methodPath.length() - 1);
                    }
                }
            }

            currentMapping.setMethodPath(methodPath);

            String fullPath;
            if (!StringUtil.isNull(basePath)) {
                String bp = basePath;
                if (bp.endsWith("/")) {
                    bp = bp.substring(0, bp.length() - 1);
                }
                if (methodPath != null) {
                    fullPath = bp + methodPath;
                } else {
                    fullPath = bp;
                }
            } else {
                fullPath = methodPath != null ? methodPath : "/";
            }

            currentMapping.setPath(fullPath);
        }
        super.visitCode();
    }

    @Override
    public void visitEnd() {
        if (currentMapping != null) {
            resource.addMapping(currentMapping);
        }
        super.visitEnd();
    }
}
