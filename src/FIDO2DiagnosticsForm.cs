using System;
using System.Text;
using System.Windows.Forms;
using KeePassPasskeyKeyProvider.WebAuthn;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Form for diagnosing FIDO2 security keys and checking PRF (Pseudo-Random Function) support
	/// </summary>
	public partial class FIDO2DiagnosticsForm : Form
	{
		private TextBox txtLog;
		private Button btnTestHmacSecret;
		private Button btnCheckApiVersion;
		private Button btnClose;
		private StringBuilder logBuilder;

		public FIDO2DiagnosticsForm()
		{
			InitializeComponent();
			logBuilder = new StringBuilder();
		}

		private void InitializeComponent()
		{
			this.txtLog = new TextBox();
			this.btnTestHmacSecret = new Button();
			this.btnCheckApiVersion = new Button();
			this.btnClose = new Button();
			this.SuspendLayout();

			// txtLog
			this.txtLog.Anchor = ((AnchorStyles)((((AnchorStyles.Top | AnchorStyles.Bottom)
				| AnchorStyles.Left)
				| AnchorStyles.Right)));
			this.txtLog.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
			this.txtLog.Location = new System.Drawing.Point(12, 12);
			this.txtLog.Multiline = true;
			this.txtLog.Name = "txtLog";
			this.txtLog.ReadOnly = true;
			this.txtLog.ScrollBars = ScrollBars.Vertical;
			this.txtLog.Size = new System.Drawing.Size(660, 380);
			this.txtLog.TabIndex = 0;

			// btnCheckApiVersion
			this.btnCheckApiVersion.Anchor = ((AnchorStyles)((AnchorStyles.Bottom | AnchorStyles.Left)));
			this.btnCheckApiVersion.Location = new System.Drawing.Point(12, 398);
			this.btnCheckApiVersion.Name = "btnCheckApiVersion";
			this.btnCheckApiVersion.Size = new System.Drawing.Size(150, 30);
			this.btnCheckApiVersion.TabIndex = 1;
			this.btnCheckApiVersion.Text = Strings.CheckApi;
			this.btnCheckApiVersion.UseVisualStyleBackColor = true;
			this.btnCheckApiVersion.Click += new EventHandler(this.BtnCheckApiVersion_Click);

			// btnTestHmacSecret
			this.btnTestHmacSecret.Anchor = ((AnchorStyles)((AnchorStyles.Bottom | AnchorStyles.Left)));
			this.btnTestHmacSecret.Location = new System.Drawing.Point(168, 398);
			this.btnTestHmacSecret.Name = "btnTestHmacSecret";
			this.btnTestHmacSecret.Size = new System.Drawing.Size(180, 30);
			this.btnTestHmacSecret.TabIndex = 2;
			this.btnTestHmacSecret.Text = Strings.PrfTest;
			this.btnTestHmacSecret.UseVisualStyleBackColor = true;
			this.btnTestHmacSecret.Click += new EventHandler(this.BtnTestHmacSecret_Click);

			// btnClose
			this.btnClose.Anchor = ((AnchorStyles)((AnchorStyles.Bottom | AnchorStyles.Right)));
			this.btnClose.Location = new System.Drawing.Point(597, 398);
			this.btnClose.Name = "btnClose";
			this.btnClose.Size = new System.Drawing.Size(75, 30);
			this.btnClose.TabIndex = 3;
			this.btnClose.Text = Strings.Close;
			this.btnClose.UseVisualStyleBackColor = true;
			this.btnClose.Click += new EventHandler(this.BtnClose_Click);

			// FIDO2DiagnosticsForm
			this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
			this.AutoScaleMode = AutoScaleMode.Font;
			this.ClientSize = new System.Drawing.Size(684, 440);
			this.Controls.Add(this.btnClose);
			this.Controls.Add(this.btnTestHmacSecret);
			this.Controls.Add(this.btnCheckApiVersion);
			this.Controls.Add(this.txtLog);
			this.MinimumSize = new System.Drawing.Size(600, 400);
			this.Name = "FIDO2DiagnosticsForm";
			this.StartPosition = FormStartPosition.CenterParent;
			this.Text = Strings.DiagnosticsTitle;
			this.Load += new EventHandler(this.FIDO2DiagnosticsForm_Load);
			this.ResumeLayout(false);
			this.PerformLayout();
		}

		private void FIDO2DiagnosticsForm_Load(object sender, EventArgs e)
		{
			Log(Strings.DiagHeader);
			Log("");
			Log(Strings.DiagIntro1);
			Log(Strings.DiagIntro2);
			Log("");
			Log(Strings.DiagIntro3);
			Log("");
			Log(Strings.DiagSteps);
			Log(Strings.DiagStep1);
			Log(Strings.DiagStep2);
			Log("");
			Log(Strings.DiagReady);
			Log("----------------------------------------");
			Log("");
		}

		private void BtnCheckApiVersion_Click(object sender, EventArgs e)
		{
			try
			{
				Log(Strings.DiagCheckingApi);
				
				if (!WebAuthnHelper.IsWebAuthnAvailable())
				{
					Log(Strings.DiagApiUnavailable);
					Log(Strings.DiagApiRequirement);
					return;
				}

				Log(Strings.DiagApiAvailable);

				uint version = WebAuthnHelper.GetApiVersion();
				Log(string.Format(Strings.DiagApiVersion, version));

				bool isPlatformAuthAvailable = false;
				int hr = WebAuthnApi.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(out isPlatformAuthAvailable);
				
				if (hr == 0)
				{
					Log($"✓ Platform Authenticator: {(isPlatformAuthAvailable ? Strings.DiagPlatformAvailable : Strings.DiagPlatformUnavailable)}");
				}
				else
				{
					Log(string.Format(Strings.DiagPlatformCheckFailed, hr));
				}

				Log("");
				Log(Strings.DiagSystemReady);
				Log("----------------------------------------");
				Log("");
			}
			catch (Exception ex)
			{
				Log(string.Format(Strings.DiagError, ex.Message));
				Log(string.Format(Strings.DiagErrorType, ex.GetType().Name));
				Log("----------------------------------------");
				Log("");
			}
		}

		private void BtnTestHmacSecret_Click(object sender, EventArgs e)
		{
			try
			{
				Log(Strings.DiagStartingPrfTest);
				Log("");

				// Warn the user
				var result = MessageBox.Show(
					Strings.DiagPrfTestConfirm,
					Strings.PrfTest,
					MessageBoxButtons.YesNo,
					MessageBoxIcon.Question);

				if (result != DialogResult.Yes)
				{
					Log(Strings.DiagTestCancelled);
					Log("----------------------------------------");
					Log("");
					return;
				}

				Log(Strings.DiagStep1Creating);

				// Generate a test User ID
				byte[] testUserId = new byte[32];
				using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
				{
					rng.GetBytes(testUserId);
				}

				Log($"  User ID: {BitConverter.ToString(testUserId, 0, 8).Replace("-", "")}... ({testUserId.Length} {Strings.Bytes})");

				// Enable logging for diagnostics
				WebAuthnHelper.Logger = (msg) => Log($"  {msg}");

				// Create the credential
				byte[] credentialId;
				byte[] creationSecret;
				try
				{
					var created = WebAuthnHelper.CreateCredential(this.Handle, testUserId, "KeePass: PRF diagnostics");
					credentialId = created.CredentialId;
					creationSecret = created.PrfSecret;
					Log(Strings.DiagCredentialCreated);
					Log($"  Credential ID: {BitConverter.ToString(credentialId, 0, Math.Min(16, credentialId.Length)).Replace("-", "")}... ({credentialId.Length} {Strings.Bytes})");
					if (creationSecret != null)
						Log(string.Format(Strings.DiagCreationSecret, creationSecret.Length));
				}
				catch (WebAuthnException ex)
				{
					Log(string.Format(Strings.DiagCreateFailed, ex.Message));
					Log("----------------------------------------");
					Log("");
					WebAuthnHelper.Logger = null;
					return;
				}

				Log("");
				Log(Strings.DiagStep2Getting);
				Log(Strings.DiagPinAgain);

				// Pause to let the operation complete
				System.Threading.Thread.Sleep(500);

				// Get the PRF secret
				byte[] prfSecret;
				try
				{
					// allowList contains only the test credential, so real database credentials are not involved
					PrfResult assertion = WebAuthnHelper.GetPrfSecret(this.Handle, new[] { credentialId });
					prfSecret = assertion.PrfSecret;

					if (prfSecret != null && prfSecret.Length > 0)
					{
						Log(Strings.DiagPrfSuccess);
						Log(string.Format(Strings.DiagSecretLength, prfSecret.Length));
						if (creationSecret != null)
						{
							bool same = creationSecret.Length == prfSecret.Length
								&& System.Linq.Enumerable.SequenceEqual(creationSecret, prfSecret);
							Log(same
								? Strings.DiagSecretMatches
								: Strings.DiagSecretMismatch);
							Array.Clear(creationSecret, 0, creationSecret.Length);
						}
						Log("");
						Log("╔════════════════════════════════════════════════════════════╗");
						Log(Strings.DiagKeySupportsPrf);
						Log(Strings.DiagKeyUsable);
						Log("╚════════════════════════════════════════════════════════════╝");
						
						// Clear the secret from memory
						Array.Clear(prfSecret, 0, prfSecret.Length);
					}
					else
					{
						Log(Strings.DiagPrfEmpty);
						Log(Strings.DiagKeyMayNotSupport);
					}
				}
				catch (WebAuthnException ex)
				{
					Log(string.Format(Strings.DiagGetSecretFailed, ex.Message));
					Log("");
					Log("╔════════════════════════════════════════════════════════════╗");
					Log(Strings.DiagKeyNoPrf);
					Log(Strings.DiagKeyNoPrfReason);
					Log("╚════════════════════════════════════════════════════════════╝");
					Log("");
					Log(Strings.DiagPossibleCauses);
					Log(Strings.DiagCause1);
					Log(Strings.DiagCause2);
					Log(Strings.DiagCause3);
					Log("");
					Log(Strings.DiagRecommendations);
					Log(Strings.DiagRecommendation1);
					Log(Strings.DiagRecommendation2);
					Log(Strings.DiagRecommendation3);
					Log(Strings.DiagRecommendation4);
				}

				// Disable logging
				WebAuthnHelper.Logger = null;

				Log("");
				Log(Strings.DiagTestFinished);
				Log("----------------------------------------");
				Log("");
			}
			catch (Exception ex)
			{
				Log(string.Format(Strings.DiagUnexpectedError, ex.Message));
				Log(string.Format(Strings.DiagErrorType, ex.GetType().Name));
				Log($"   Stack Trace: {ex.StackTrace}");
				Log("----------------------------------------");
				Log("");
				WebAuthnHelper.Logger = null;
			}
		}

		private void BtnClose_Click(object sender, EventArgs e)
		{
			this.Close();
		}

		private void Log(string message)
		{
			logBuilder.AppendLine(message);
			txtLog.Text = logBuilder.ToString();
			txtLog.SelectionStart = txtLog.Text.Length;
			txtLog.ScrollToCaret();
			Application.DoEvents(); // Refresh the UI
		}
	}
}

