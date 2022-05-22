using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JobCoinAPI.Models;
using JobCoinAPI.ViewModels.LoginViewModels;
using Microsoft.IdentityModel.Tokens;

namespace JobCoinAPI.Shared
{
	public class Seguranca
	{
        private static List<(string, string)> _refreshTokens = new List<(string, string)>();

        public static void SalvarRefreshToken(string email, string refreshToken)
		{
            _refreshTokens.Add(new(email, refreshToken));
        }
        
        public static string GetRefreshToken(string email)
        {
            return _refreshTokens.FirstOrDefault(refreshToken => refreshToken.Item1 == email).Item2;
        }

        public static void DeletarRefreshToken(string email, string refreshToken)
        {
            var item = _refreshTokens.FirstOrDefault(rt => rt.Item1 == email
                && rt.Item2 == refreshToken);

            _refreshTokens.Remove(item);
        }

        public static string GeradorSenhaHash(string senha)
        {
            StringBuilder sb = new StringBuilder();

            using (SHA256 hash = SHA256.Create())
            {
                Encoding encode = Encoding.UTF8;
                byte[] resultado = hash.ComputeHash(encode.GetBytes(senha));

                foreach (byte b in resultado)
                {
                    sb.Append(b.ToString("x2"));
                }
            }

            return sb.ToString();
        }

        public static TokenViewModel GerarToken(Autenticacao autenticacao, Usuario usuario, IEnumerable<Claim> claims)
        {
            DateTime creationDate = DateTime.Now;
            DateTime expirationDate = creationDate + TimeSpan.FromHours(2);
            claims = claims ?? new Claim[]
            {
                new Claim(ClaimTypes.NameIdentifier, usuario.IdUsuario.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, usuario.Email),
                new Claim(ClaimTypes.Role, usuario.Perfil.NomePerfil)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                NotBefore = creationDate.ToUniversalTime(),
                Expires = expirationDate.ToUniversalTime(),
                SigningCredentials = autenticacao.SigningCredentials
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            var tokenViewModel = new TokenViewModel
            {
                Autenticado = true,
                DataCriacao = creationDate.ToString("yyyy-MM-dd HH:mm:ss"),
                DataExpiracao = expirationDate.ToString("yyyy-MM-dd HH:mm:ss"),
                Token = tokenHandler.WriteToken(token)
            };

            return tokenViewModel;
        }

        public static string GerarRefreshToken()
		{
            return $"{Guid.NewGuid().ToString()}-{Guid.NewGuid().ToString()}";
		}

        public static ClaimsPrincipal ExtrairClaimsTokenAntigo(Autenticacao autenticacao, string token)
		{
            var parametrosToken = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = autenticacao.Key,
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, parametrosToken, out var securityToken);

            if (securityToken is not JwtSecurityToken)
                throw new SecurityTokenException("Token inválido !");

            return principal;
		}
    }
}