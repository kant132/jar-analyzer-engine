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
import me.n1ar4.jar.analyzer.analyze.jaxrs.JaxRsResource;
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

public class JaxRsClassVisitor extends ClassVisitor {
    private final Map<ClassReference.Handle, ClassReference> classMap;
    private final Map<MethodReference.Handle, MethodReference> methodMap;
    private final List<JaxRsResource> resources;
    private boolean isJaxRs;
    private JaxRsResource currentResource;
    private String name;
    private JaxRsPathAnnoAdapter pathAnnoAdapter = null;

    public JaxRsClassVisitor(List<JaxRsResource> resources,
                             Map<ClassReference.Handle, ClassReference> classMap,
                             Map<MethodReference.Handle, MethodReference> methodMap) {
        super(EngineConst.ASMVersion);
        this.methodMap = methodMap;
        this.resources = resources;
        this.classMap = classMap;
    }

    @Override
    public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
        AnnotationVisitor av = super.visitAnnotation(descriptor, visible);
        if (descriptor.equals(JaxRsConstant.JAVAX_PATH_ANNO) ||
                descriptor.equals(JaxRsConstant.JAKARTA_PATH_ANNO)) {
            this.pathAnnoAdapter = new JaxRsPathAnnoAdapter(EngineConst.ASMVersion, av);
            return this.pathAnnoAdapter;
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
        boolean hasPath = false;
        for (AnnoReference anno : annotations) {
            if (anno.getAnnoName().equals(JaxRsConstant.JAVAX_PATH_ANNO) ||
                    anno.getAnnoName().equals(JaxRsConstant.JAKARTA_PATH_ANNO)) {
                hasPath = true;
                break;
            }
        }
        if (hasPath) {
            this.isJaxRs = true;
            currentResource = new JaxRsResource();
            currentResource.setClassReference(cr);
            currentResource.setClassName(new ClassReference.Handle(name));
            if (pathAnnoAdapter != null) {
                if (!pathAnnoAdapter.getResults().isEmpty()) {
                    currentResource.setBasePath(pathAnnoAdapter.getResults().get(0));
                }
            }
        }
        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor,
                                     String signature, String[] exceptions) {
        MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
        if (this.isJaxRs) {
            if (name.equals("<init>") || name.equals("<clinit>")) {
                return mv;
            }
            if (pathAnnoAdapter != null) {
                if (!pathAnnoAdapter.getResults().isEmpty()) {
                    currentResource.setBasePath(pathAnnoAdapter.getResults().get(0));
                }
            }
            return new JaxRsMethodAdapter(name, descriptor, this.name, EngineConst.ASMVersion, mv,
                    currentResource, this.methodMap);
        } else {
            return mv;
        }
    }

    @Override
    public void visitEnd() {
        if (isJaxRs) {
            resources.add(currentResource);
        }
        super.visitEnd();
    }
}
