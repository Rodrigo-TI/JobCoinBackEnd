using System.ComponentModel.DataAnnotations;

namespace JobCoinAPI.ViewModels.LoginViewModels
{
	public class RefreshTokenViewModel
	{
		[Required(AllowEmptyStrings = false)]
		[DisplayFormat(ConvertEmptyStringToNull = false)]
		public string Token { get; set; }

		[Required(AllowEmptyStrings = false)]
		[DisplayFormat(ConvertEmptyStringToNull = false)]
		public string RefreshToken { get; set; }
	}
}