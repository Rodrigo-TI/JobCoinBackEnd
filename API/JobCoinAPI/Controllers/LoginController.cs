﻿using System;
using System.Linq;
using System.Threading.Tasks;
using JobCoinAPI.Data;
using JobCoinAPI.Shared;
using JobCoinAPI.ViewModels.LoginViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace JobCoinAPI.Controllers
{
	/// <response code="200">Ok</response>
	/// <response code="400">Bad Request</response>
	/// <response code="404">Not Found</response>
	/// <response code="500">Internal Server Error</response>
	[ApiController]
	[Route("v1")]
	public class LoginController : ControllerBase
	{
		[HttpPost]
		[Route("login")]
		public async Task<IActionResult> Authenticate(
			[FromServices] DataContext context,
			[FromServices] Autenticacao autenticacao,
			[FromBody] LoginUsuarioViewModel loginUsuarioViewModel)
		{
			if (!ModelState.IsValid)
				return BadRequest();

			try
			{
				var senha = Seguranca.GeradorSenhaHash(loginUsuarioViewModel.Senha);

				var usuarioByLogin = await context.Usuarios
					.AsNoTracking()
					.Include(usuario => usuario.Perfil)
					.Where(usuario => usuario.Email.ToLower().Equals(loginUsuarioViewModel.Email.ToLower())
						&& usuario.Senha.Equals(senha))
					.FirstOrDefaultAsync();

				if (usuarioByLogin == null)
					return BadRequest("Usuário ou senha inválidos.");

				var token = Seguranca.GerarToken(autenticacao, usuarioByLogin, null);
				var refreshToken = Seguranca.GerarRefreshToken();

				Seguranca.SalvarRefreshToken(usuarioByLogin.Email, refreshToken);

				return Ok(new { token = token, refreshToken = refreshToken });
			}
			catch (Exception)
			{
				return StatusCode(500);
			}
		}

		[HttpPost]
		[Route("refresh")]
		public IActionResult Refresh(
			[FromServices] Autenticacao autenticacao,
			[FromBody] RefreshTokenViewModel refreshTokenViewModel)
		{
			var principal = Seguranca.ExtrairClaimsTokenAntigo(autenticacao, refreshTokenViewModel.Token);
			var email = principal.Claims.FirstOrDefault(i => i.Type.Contains("emailaddress")).Value;
			var refreshTokenSalvo = Seguranca.GetRefreshToken(email);

			if (refreshTokenSalvo != refreshTokenViewModel.RefreshToken)
				throw new SecurityTokenException("Refresh token inválido !");

			var novoToken = Seguranca.GerarToken(autenticacao, null, principal.Claims);
			var novoRefreshToken = Seguranca.GerarRefreshToken();

			Seguranca.DeletarRefreshToken(email, refreshTokenViewModel.RefreshToken);
			Seguranca.SalvarRefreshToken(email, novoRefreshToken);

			return new ObjectResult(new
			{
				token = novoToken,
				refreshToken = novoRefreshToken
			});
		}
	}
}