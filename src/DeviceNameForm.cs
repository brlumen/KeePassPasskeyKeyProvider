using System.Windows.Forms;

namespace KeePassFIDO2
{
	/// <summary>
	/// Диалог перед созданием credential для мастер‑ключа: пояснение и название устройства
	/// </summary>
	public partial class DeviceNameForm : Form
	{
		public DeviceNameForm()
		{
			InitializeComponent();
			labelDescription.Text =
				"Сейчас будет создан новый FIDO2 credential для этой базы данных.\n" +
				"Введите ниже название устройства, которым создаётся ключ — оно отличает его от других " +
				"в списке устройств базы. Если оставить пустым, подпись будет составлена из типа устройства и даты.\n\n" +
				"Вам потребуется:\n" +
				"1. FIDO2‑ключ с поддержкой hmac-secret/PRF (YubiKey 5 и др.), Windows Hello или телефон\n" +
				"2. Ввести PIN‑код ключа\n" +
				"3. Подтвердить создание credential (обычно нажатием кнопки на ключе)\n\n" +
				"Credential сохраняется на самом устройстве — файлы рядом с базой не нужны.\n" +
				"Другие устройства: Файл → Параметры базы → вкладка «FIDO2».";
		}

		/// <summary>Введённое название без пробелов по краям; пусто, если не указано. Доступно и после закрытия формы</summary>
		public string DeviceName { get; private set; } = string.Empty;

		protected override void OnFormClosing(FormClosingEventArgs e)
		{
			DeviceName = textBoxDeviceName.Text.Trim();
			base.OnFormClosing(e);
		}
	}
}
