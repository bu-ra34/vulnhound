# vulnhound

**Gerçek zafiyetleri bulur. Kanıtlar. Düzeltir. Token'larını yakmadan.**

> Durum: pre-alpha. Şu an yalnızca `estimate` ve `version` çalışıyor; gerisi yol haritasında.

[English](README.md)

## Neden

Bir LLM'den kod tabanını güvenlik açısından incelemesini istemek genellikle tüm repoyu
ona okutmak demektir. Bu pahalı ve yavaştır; harcanan token'ların çoğu zafiyetle ilgisiz
koddur. vulnhound önce ucuz statik analizle aday akışları bulur; LLM yalnızca kısa bir
liste ve küçük kod parçaları okur.

## Nasıl çalışır

- **Çekirdek gözdür.** Yalnızca standart kütüphane kullanan Python programı bir AST
  indeksi oluşturur ve güvenilmeyen kaynaklardan tehlikeli çıkışlara (sink) taint analizi
  yapar. Hiçbir zaman LLM çağırmaz, kısa JSON üretir.
- **Claude beyindir.** Claude Code içinde, pakete dahil skill Claude'a CLI'ı çalıştırmasını,
  yalnızca bu çıktıyı ve küçük kod parçalarını okumasını, her bulguyu değerlendirmesini,
  muhtemelen gerçek olanlar için PoC yazıp sandbox içinde kanıtlamasını ve yama yapmasını söyler.

Çalışma zamanı bağımlılığı yok. Python 3.10+. MIT lisanslı.

## Kurulum

Claude Code eklentisi olarak:

```
/plugin marketplace add bu-ra34/vulnhound
/plugin install vulnhound@vulnhound
```

CLI'ın kendisi (skill'in PATH üzerinde olmasına ihtiyacı var):

```
pip install vulnhound
```

## CLI

| Komut | Ne yapar |
|---|---|
| `vulnhound analyze [path] [--json] [--no-cache] [--min-severity S]` | Aday zafiyetleri bulur. Bulgu varsa çıkış kodu 1. Aynı sink/yardımcıyı paylaşan bulgular gruplanır (`--no-group` hepsini listeler); tests/examples/docs dizinleri ve `test_*.py` `--include-tests` verilmedikçe atlanır; `--include-local-sources` yerel/CLI girdilerini kaynak sayar. |
| `vulnhound slice <id>` | Bir bulgu için minimal kod parçası. |
| `vulnhound prove <id> --poc FILE [--root DIR] [--backend auto\|docker\|unshare] [--timeout S] [--json] [--verbose]` | PoC'yi sandbox içinde (ağsız, kaynak sınırlı) çalıştırır. PROVEN (çıkış 0), SAFE (1) veya UNVERIFIED (3) yazar. |
| `vulnhound estimate [path] [--json]` | Tüm repoyu okumanın yaklaşık token maliyeti (bayt/4). |
| `vulnhound report [--format json\|sarif\|markdown] [-o FILE]` | Bulguları raporlar. |
| `vulnhound version` | Sürümü yazar. |

Çıkış kodları: 0 tamam / bulgu yok, 1 bulgu var, 2 kullanım hatası (örn. bilinmeyen id), 3 UNVERIFIED (prove).

## Bir bulguyu kanıtlama

`vulnhound prove <id> --poc poc.py`, küçük bağımsız bir Python PoC'sini sandbox içinde (ağ kapalı, bellek/CPU/süre sınırlı, proje salt okunur) çalıştırır ve karar bildirir. PoC, zafiyetli kodu kötü niyetli girdiyle tetikler; sömürü işe yararsa `vulnhound.poc` içinden `proven("ayrıntı")`, engellenirse `safe("ayrıntı")` çağırır. `canary_path()`, path traversal PoC'lerinin okuması için proje dışında gizli bir dosya verir. İşaret yok ve çıkış 0 ise SAFE; sandbox yoksa, zaman aşımı olursa ya da PoC çökerse UNVERIFIED. PoC hiçbir zaman ana makinede çalışmaz.

Not: sandbox için docker veya unshare gerekir. PoC projenize karşı çalışır, bu yüzden üçüncü taraf importları sandbox içinde bulunabilir olmalıdır: `unshare` arka ucu ana makinenin venv'ini salt okunur görür, `docker` arka ucu ise temiz bir python imajı kullanır; framework importu gereken PoC'ler orada UNVERIFIED çıkabilir. PoC kurulu bağımlılıkları import ediyorsa `--backend unshare` seçin.

## Yol haritası

- [x] M0: iskelet (CLI, eklenti, skill, CI)
- [ ] M1: proje indeksi (AST, çağrı grafı, önbellek)
- [ ] M2: taint motoru
- [ ] M3: framework desteği ve `slice`
- [ ] M4: sandbox içinde kanıt (`prove`)
- [ ] M5: benchmark
- [ ] M6: sürüm

Henüz ölçülmüş bir benchmark sonucu iddia edilmiyor; M5 sonrası yayımlanacak.

## Güvenlik

Yalnızca kendi kodunuzu tarayın. Bkz. [SECURITY.md](SECURITY.md).

## Lisans

MIT
