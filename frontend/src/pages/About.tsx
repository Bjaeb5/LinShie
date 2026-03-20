import { Shield, Send, GraduationCap, Code, Globe, BookOpen, Award } from 'lucide-react'
import { useLang } from '../i18n'

export default function About() {
  const { lang } = useLang()

  return (
    <div className="p-6 space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Shield className="w-6 h-6 text-blue-400" />
          {lang === 'ru' ? 'О создателе' : 'About Creator'}
        </h1>
      </div>

      {/* Creator card */}
      <div className="bg-gradient-to-br from-gray-900 to-gray-800 border border-gray-700 rounded-2xl p-8">
        <div className="flex flex-col sm:flex-row items-start gap-6">
          {/* Avatar */}
          <div className="flex-shrink-0">
            <div className="w-24 h-24 bg-gradient-to-br from-blue-500 to-cyan-600 rounded-2xl flex items-center justify-center shadow-2xl shadow-blue-900/40">
              <span className="text-4xl font-bold text-white">А</span>
            </div>
          </div>

          {/* Info */}
          <div className="flex-1">
            <h2 className="text-2xl font-bold text-white mb-1">Айдар Ахманов</h2>
            <p className="text-blue-400 font-medium mb-4">Aidar Akhmanov</p>

            <div className="space-y-3">
              <div className="flex items-start gap-3">
                <GraduationCap className="w-5 h-5 text-gray-400 mt-0.5 flex-shrink-0" />
                <div>
                  <div className="text-sm font-medium text-white">
                    {lang === 'ru' ? 'Магистрант' : 'Master\'s Student'}
                  </div>
                  <div className="text-sm text-gray-400">
                    {lang === 'ru'
                      ? 'Евразийский Национальный университет имени Л.Н. Гумилева'
                      : 'L.N. Gumilyov Eurasian National University'}
                  </div>
                  <div className="text-xs text-blue-400 mt-0.5">
                    {lang === 'ru' ? 'Специальность: Системы информационной безопасности' : 'Specialization: Information Security Systems'}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <Send className="w-5 h-5 text-blue-400 flex-shrink-0" />
                <a href="https://t.me/Bjebs" target="_blank" rel="noopener noreferrer"
                  className="text-blue-400 hover:text-blue-300 font-medium transition-colors">
                  @Bjebs
                  <span className="text-gray-500 text-sm ml-2">Telegram</span>
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* About the project */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="bg-gradient-to-br from-blue-500 to-cyan-600 p-2 rounded-xl">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">LinShi</h3>
            <p className="text-xs text-gray-400">Linux Shield — Security Audit Platform</p>
          </div>
        </div>

        <p className="text-gray-300 text-sm leading-relaxed mb-4">
          {lang === 'ru'
            ? 'LinShi — практическая часть магистерской диссертации на тему "Исследование комплексных методов защиты физических и виртуальных Linux-серверов в условиях современных киберугроз". Система представляет собой веб-платформу для автоматизированного аудита безопасности Linux-серверов.'
            : 'LinShi is the practical part of a master\'s thesis on "Research of comprehensive methods for protecting physical and virtual Linux servers in the context of modern cyber threats". The system is a web platform for automated security auditing of Linux servers.'}
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {[
            { icon: BookOpen, title: lang === 'ru' ? 'Стандарты' : 'Standards', items: ['CIS Benchmarks v8', 'NIST SP 800-53', 'OWASP Top 10'] },
            { icon: Code, title: lang === 'ru' ? 'Технологии' : 'Technologies', items: ['FastAPI + Python', 'React + TypeScript', 'Docker Compose'] },
            { icon: Globe, title: lang === 'ru' ? 'Возможности' : 'Features', items: [lang === 'ru' ? '150+ проверок безопасности' : '150+ security checks', lang === 'ru' ? 'Удалённое сканирование SSH' : 'Remote SSH scanning', lang === 'ru' ? 'Групповые политики' : 'Group Policies'] },
            { icon: Award, title: lang === 'ru' ? 'Соответствие' : 'Compliance', items: ['CIS Level 1 & 2', 'NIST AC/AU/CM/IA/SC', 'OWASP A01-A10'] },
          ].map(({ icon: Icon, title, items }) => (
            <div key={title} className="bg-gray-800/50 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <Icon className="w-4 h-4 text-blue-400" />
                <span className="text-sm font-medium text-white">{title}</span>
              </div>
              <ul className="space-y-1">
                {items.map(item => (
                  <li key={item} className="text-xs text-gray-400 flex items-center gap-1.5">
                    <span className="w-1 h-1 bg-blue-500 rounded-full flex-shrink-0" />{item}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>

      {/* Research context */}
      <div className="bg-gradient-to-r from-blue-900/20 to-cyan-900/20 border border-blue-800/40 rounded-2xl p-6">
        <h3 className="text-lg font-bold text-white mb-3">
          {lang === 'ru' ? '📚 Научный контекст' : '📚 Research Context'}
        </h3>
        <p className="text-gray-300 text-sm leading-relaxed">
          {lang === 'ru'
            ? 'Данный проект разработан в рамках магистерской программы по информационной безопасности. Исследование охватывает современные угрозы безопасности Linux-инфраструктуры, методы автоматизированного аудита и практики применения международных стандартов кибербезопасности в реальных серверных окружениях.'
            : 'This project was developed as part of a master\'s program in information security. The research covers modern threats to Linux infrastructure security, automated audit methods and practices of applying international cybersecurity standards in real server environments.'}
        </p>
        <div className="mt-4 flex flex-wrap gap-2">
          {['#LinuxSecurity', '#CyberSecurity', '#InfoSec', '#NIST', '#CISBenchmarks', '#MasterThesis'].map(tag => (
            <span key={tag} className="text-xs bg-blue-900/40 text-blue-300 border border-blue-800/50 px-2.5 py-1 rounded-lg">{tag}</span>
          ))}
        </div>
      </div>
    </div>
  )
}
