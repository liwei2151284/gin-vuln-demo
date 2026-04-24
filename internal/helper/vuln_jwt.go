// [SCA场景一 + 场景二] 直接依赖 CVE + 废弃包
// github.com/dgrijalva/jwt-go v3.2.0+incompatible
// CVE-2020-26160：audience claim 未严格校验，可绕过 token 验证
// 仓库已被作者 archived，官方建议迁移至 github.com/golang-jwt/jwt/v5
package helper

import jwt "github.com/dgrijalva/jwt-go"

// ParseLegacyJWT 使用存在 CVE-2020-26160 的 jwt-go v3.2.0（故意预埋）
func ParseLegacyJWT(tokenStr, secret string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	return token.Claims.(jwt.MapClaims), nil
}
