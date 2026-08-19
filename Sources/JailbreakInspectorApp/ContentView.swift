import SwiftUI
import JailbreakInspector

final class DetectionViewModel: ObservableObject {
    @Published var results: [DetectionResult] = []
    @Published var summary: String = "Scanning…"

    init() {
        refresh()
    }

    func refresh() {
        let engine = DetectionEngine()
        let all = engine.evaluate()
        results = all.sorted {
            if $0.detected == $1.detected {
                return $0.severity > $1.severity
            }
            return $0.detected && !$1.detected
        }

        let positives = results.filter(\.detected)
        summary = positives.isEmpty
            ? "No suspicious indicators were detected during this scan."
            : "\(positives.count) suspicious indicator(s) across \(Set(positives.map { $0.category.rawValue }).count) category group(s)."
    }
}

struct ContentView: View {
    @StateObject private var viewModel = DetectionViewModel()

    var body: some View {
        NavigationStack {
            List {
                Section("Overview") {
                    Text(viewModel.summary)
                        .font(.headline)
                    Button("Refresh scan") {
                        viewModel.refresh()
                    }
                    .buttonStyle(.borderedProminent)
                }

                ForEach(viewModel.results) { result in
                    Section(header: Text(result.category.rawValue)) {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text(result.name)
                                    .font(.headline)
                                Spacer()
                                Text(result.detected ? "Detected" : "Clean")
                                    .font(.caption)
                                    .padding(6)
                                    .foregroundColor(result.detected ? .red : .green)
                                    .background(result.detected ? Color.red.opacity(0.12) : Color.green.opacity(0.12))
                                    .clipShape(Capsule())
                            }

                            Text(result.explanation)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)

                            if let details = result.technicalDetails {
                                Text(details)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }

                            HStack {
                                Text("Severity: \(result.severity)")
                                    .font(.caption)
                                Spacer()
                                if result.detected {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundStyle(.orange)
                                } else {
                                    Image(systemName: "checkmark.shield.fill")
                                        .foregroundStyle(.green)
                                }
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }
            }
            .navigationTitle("Jailbreak Inspector")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Refresh") {
                        viewModel.refresh()
                    }
                }
            }
        }
    }
}

#Preview {
    ContentView()
}
