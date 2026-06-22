/*
 * GPLv3 License
 *
 * Copyright (c) 2022-2026 4ra1n (Jar Analyzer Team)
 *
 * This project is distributed under the GPLv3 license.
 *
 * https://github.com/jar-analyzer/jar-analyzer/blob/master/LICENSE
 */

package me.n1ar4.jar.analyzer.analyze.jaxws.asm;

import me.n1ar4.jar.analyzer.analyze.jaxws.JaxWsConstant;
import me.n1ar4.jar.analyzer.analyze.jaxws.JaxWsEndpoint;
import me.n1ar4.jar.analyzer.core.reference.AnnoReference;
import me.n1ar4.jar.analyzer.core.reference.ClassReference;
import me.n1ar4.jar.analyzer.core.reference.MethodReference;
import me.n1ar4.jar.analyzer.engine.EngineConst;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;

import java.util.List;
import java.util.Map;
import java.util.Set;

public class JaxWsClassVisitor extends ClassVisitor {
    private final Map<ClassReference.Handle, ClassReference> classMap;
    private final Map<MethodReference.Handle, MethodReference> methodMap;
    private final List<JaxWsEndpoint> endpoints;
    private boolean isJaxWs;
    private JaxWsEndpoint currentEndpoint;
    private String name;
    private JaxWsAnnoAdapter webServiceAnnoAdapter = null;

    public JaxWsClassVisitor(List<JaxWsEndpoint> endpoints,
                             Map<ClassReference.Handle, ClassReference> classMap,
                             Map<MethodReference.Handle, MethodReference> methodMap) {
        super(EngineConst.ASMVersion);
        this.methodMap = methodMap;
        this.endpoints = endpoints;
        this.classMap = classMap;
    }

    @Override
    public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
        AnnotationVisitor av = super.visitAnnotation(descriptor, visible);
        if (descriptor.equals(JaxWsConstant.JAVAX_WEBSERVICE_ANNO) ||
                descriptor.equals(JaxWsConstant.JAKARTA_WEBSERVICE_ANNO)) {
            this.webServiceAnnoAdapter = new JaxWsAnnoAdapter(EngineConst.ASMVersion, av);
            return this.webServiceAnnoAdapter;
        }
        return av;
    }

    @Override
    public void visit(int version, int access, String name, String signature,
                      String superName, String[] interfaces) {
        this.name = name;
        ClassReference cr = classMap.get(new ClassReference.Handle(name));
        if (cr == null) {
            super.visit(version, access, name, signature, superName, interfaces);
            return;
        }
        Set<AnnoReference> annotations = cr.getAnnotations();
        boolean hasWebService = false;
        for (AnnoReference anno : annotations) {
            if (anno.getAnnoName().equals(JaxWsConstant.JAVAX_WEBSERVICE_ANNO) ||
                    anno.getAnnoName().equals(JaxWsConstant.JAKARTA_WEBSERVICE_ANNO)) {
                hasWebService = true;
                break;
            }
        }
        if (hasWebService) {
            this.isJaxWs = true;
            currentEndpoint = new JaxWsEndpoint();
            currentEndpoint.setClassReference(cr);
            currentEndpoint.setClassName(new ClassReference.Handle(name));
            if (webServiceAnnoAdapter != null) {
                currentEndpoint.setServiceName(webServiceAnnoAdapter.getServiceName());
                currentEndpoint.setEndpointInterface(webServiceAnnoAdapter.getEndpointInterface());
            }
        }
        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor,
                                     String signature, String[] exceptions) {
        MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
        if (this.isJaxWs) {
            if (name.equals("<init>") || name.equals("<clinit>")) {
                return mv;
            }
            return new JaxWsMethodAdapter(name, descriptor, this.name, EngineConst.ASMVersion, mv,
                    currentEndpoint, this.methodMap);
        } else {
            return mv;
        }
    }

    @Override
    public void visitEnd() {
        if (isJaxWs) {
            endpoints.add(currentEndpoint);
        }
        super.visitEnd();
    }
}
