package com.senior.cyber.pki.root.web.provider;

import com.senior.cyber.frmk.common.model.BrandColor;
import com.senior.cyber.frmk.common.model.Theme;
import com.senior.cyber.frmk.common.provider.IThemeProvider;

public class MemoryThemeProvider implements IThemeProvider {

    @Override
    public Theme fetchTheme() {
        Theme theme = new Theme();
        theme.setBrandColor(BrandColor.Light);
        return theme;
    }

}
