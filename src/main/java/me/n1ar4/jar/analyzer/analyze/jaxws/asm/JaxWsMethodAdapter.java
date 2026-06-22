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
import me.n1ar4.jar.analyzer.analyze.jaxws.JaxWsOperation;
import me.n1ar4.jar.analyzer.core.reference.ClassReference;
import me.n1ar4.jar.analyzer.core.reference.MethodReference;
import me.n1ar4.jar.analyzer.engine.EngineConst;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.MethodVisitor;

import java.util.Map;

public class JaxWsMethodAdapter extends MethodVisitor {
    private final Map<MethodReference.Handle, MethodReference> methodMap;
    private final JaxWsEndpoint endpoint;
    private final String name;
    private final String owner;
    private final String desc;

    private JaxWsOperation currentOperation;
    private JaxWsAnnoAdapter webMethodAnnoAdapter = null;

    public JaxWsMethodAdapter(String name, String descriptor, String owner,
                              int api, MethodVisitor methodVisitor,
                              JaxWsEndpoint currentEndpoint,
                              Map<MethodReference.Handle, MethodReference> methodMap) {
        super(api, methodVisitor);
        this.owner = owner;
        this.desc = descriptor;
        this.name = name;
        this.methodMap = methodMap;
        this.endpoint = currentEndpoint;
    }

    @Override
    public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
        AnnotationVisitor av = super.visitAnnotation(descriptor, visible);
        if (descriptor.equals(JaxWsConstant.JAVAX_WEBMETHOD_ANNO) ||
                descriptor.equals(JaxWsConstant.JAKARTA_WEBMETHOD_ANNO)) {
            if (currentOperation == null) {
                currentOperation = new JaxWsOperation();
            }
            webMethodAnnoAdapter = new JaxWsAnnoAdapter(EngineConst.ASMVersion, av);
            return webMethodAnnoAdapter;
        }
        return av;
    }

    @Override
    public void visitCode() {
        if (this.currentOperation != null) {
            currentOperation.setMethodName(new MethodReference.Handle(
                    new ClassReference.Handle(this.owner), this.name, this.desc));
            currentOperation.setMethodReference(methodMap.get(currentOperation.getMethodName()));
            if (webMethodAnnoAdapter != null) {
                currentOperation.setExclude(webMethodAnnoAdapter.isExclude());
                currentOperation.setAction(webMethodAnnoAdapter.getAction());
            }
        }
        super.visitCode();
    }

    @Override
    public void visitEnd() {
        if (currentOperation != null) {
            endpoint.addOperation(currentOperation);
        }
        super.visitEnd();
    }
}
