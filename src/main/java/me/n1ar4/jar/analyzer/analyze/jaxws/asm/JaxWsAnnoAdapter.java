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

import org.objectweb.asm.AnnotationVisitor;

public class JaxWsAnnoAdapter extends AnnotationVisitor {
    private String serviceName;
    private String endpointInterface;
    private boolean exclude;
    private String action;
    private String value;

    public JaxWsAnnoAdapter(int api, AnnotationVisitor annotationVisitor) {
        super(api, annotationVisitor);
    }

    public String getServiceName() {
        return serviceName;
    }

    public String getEndpointInterface() {
        return endpointInterface;
    }

    public boolean isExclude() {
        return exclude;
    }

    public String getAction() {
        return action;
    }

    public String getValue() {
        return value;
    }

    @Override
    public void visit(String name, Object value) {
        if (name != null && value != null) {
            String strValue = value.toString();
            switch (name) {
                case "serviceName":
                    this.serviceName = strValue;
                    break;
                case "endpointInterface":
                    this.endpointInterface = strValue;
                    break;
                case "exclude":
                    this.exclude = Boolean.parseBoolean(strValue);
                    break;
                case "action":
                    this.action = strValue;
                    break;
                case "value":
                    this.value = strValue;
                    break;
                default:
                    break;
            }
        }
        super.visit(name, value);
    }
}
