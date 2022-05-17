using System;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;

namespace JobCoinAPI
{
	public class Program
	{
		public static void Main(string[] args)
		{
			CreateHostBuilder(args).Build().Run();
		}

		public static IHostBuilder CreateHostBuilder(string[] args)
		{
			return Host.CreateDefaultBuilder(args)
				.ConfigureWebHostDefaults(webBuilder =>
				{
					var porta = Environment.GetEnvironmentVariable("PORT") ?? "5000";

					webBuilder.UseStartup<Startup>()
					.UseUrls("http://*:" + porta);
				});
		}
	}
}